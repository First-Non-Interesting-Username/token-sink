"""Common provider adapter interface (spec §7).

Every adapter — native, gateway, or user-supplied custom — implements
:class:`ProviderAdapter`. The interface is intentionally small:

* :meth:`chat` — fire-and-await one completion
* :meth:`stream` — async iterator of content chunks
* :meth:`health` — connectivity check
* :meth:`models` — declarative list of known models with their free
  status and capabilities

Adapters never log secrets. They translate provider-specific errors into
:class:`mavr.schemas.routing.ProviderError`, with a normalized reason and
a ``retryable`` hint the router uses to drive its circuit breaker.
"""
from __future__ import annotations

import abc
import asyncio
from collections.abc import AsyncGenerator
from dataclasses import dataclass, field
from typing import Any

from mavr.schemas.routing import (
    AdapterCapabilities,
    ChatRequest,
    ChatResponse,
    HealthReport,
    ModelCatalogEntry,
    ProviderError,
    ProviderErrorReason,
    UsageInfo,
)
from mavr.schemas.routing import AuthStatusStr as _AuthStatusStr  # noqa: F401

# ---- metadata -----------------------------------------------------------


@dataclass(frozen=True)
class AdapterAuth:
    """Auth descriptor for an adapter. The secret value is never stored here."""

    secret_name: str | None = None
    required: bool = True
    last_status: str = "missing"  # ok|missing|invalid

    def status(self) -> str:
        return self.last_status


@dataclass(frozen=True)
class AdapterMetadata:
    """Static, non-secret facts about an adapter.

    This is what the registry, the CLI, and the future UI read.
    """

    provider_id: str
    display_name: str
    kind: str  # native|gateway|custom
    base_url: str | None = None
    notes: str = ""
    capabilities: AdapterCapabilities = field(default_factory=AdapterCapabilities)
    auth: AdapterAuth = field(default_factory=AdapterAuth)


# ---- streaming chunk type ----------------------------------------------


@dataclass(frozen=True)
class ChatStream:
    content: str
    finish_reason: str = ""
    usage: UsageInfo = field(default_factory=UsageInfo)
    tool_calls: list[dict[str, Any]] = field(default_factory=list)


# ---- error normalization helpers ---------------------------------------


def normalize_http_error(
    *,
    provider_id: str,
    http_status: int | None,
    message: str,
) -> ProviderError:
    """Translate a provider HTTP error into a normalized :class:`ProviderError`."""

    if http_status is None:
        return ProviderError(
            ProviderErrorReason.NETWORK,
            f"{provider_id}: network error: {message}",
            retryable=True,
            provider_id=provider_id,
        )
    if http_status in (401, 403):
        return ProviderError(
            ProviderErrorReason.AUTH,
            f"{provider_id}: auth failure ({http_status}): {message}",
            retryable=False,
            http_status=http_status,
            provider_id=provider_id,
        )
    if http_status == 408 or http_status >= 500:
        return ProviderError(
            ProviderErrorReason.OVERLOADED,
            f"{provider_id}: server error ({http_status}): {message}",
            retryable=True,
            http_status=http_status,
            provider_id=provider_id,
        )
    if http_status == 429:
        return ProviderError(
            ProviderErrorReason.RATE_LIMIT,
            f"{provider_id}: rate limited: {message}",
            retryable=True,
            http_status=http_status,
            provider_id=provider_id,
        )
    if 400 <= http_status < 500:
        return ProviderError(
            ProviderErrorReason.MODEL_ERROR,
            f"{provider_id}: client error ({http_status}): {message}",
            retryable=False,
            http_status=http_status,
            provider_id=provider_id,
        )
    return ProviderError(
        ProviderErrorReason.UNKNOWN,
        f"{provider_id}: unknown error ({http_status}): {message}",
        retryable=False,
        http_status=http_status,
        provider_id=provider_id,
    )


def normalize_timeout_error(provider_id: str, message: str) -> ProviderError:
    return ProviderError(
        ProviderErrorReason.TIMEOUT,
        f"{provider_id}: timeout: {message}",
        retryable=True,
        provider_id=provider_id,
    )


# ---- adapter ABC -------------------------------------------------------


class ProviderAdapter(abc.ABC):
    """Provider-agnostic adapter.

    Adapters are stateless aside from the optional :class:`AdapterAuth`
    handle (which never holds the secret in memory; the secret is read
    fresh from the keyring inside :meth:`_get_secret`).
    """

    def __init__(self, metadata: AdapterMetadata) -> None:
        self._metadata = metadata

    # -- introspection --------------------------------------------------

    @property
    def metadata(self) -> AdapterMetadata:
        return self._metadata

    @property
    def provider_id(self) -> str:
        return self._metadata.provider_id

    @property
    def capabilities(self) -> AdapterCapabilities:
        return self._metadata.capabilities

    # -- model catalog (declarative) -----------------------------------

    @abc.abstractmethod
    def models(self) -> list[ModelCatalogEntry]:
        """Return the adapter's known models.

        Each entry must declare ``free`` and ``free_status``. Adapters
        should never assume a gateway is partly-free and propagate the
        assumption to specific models — the per-model metadata is the
        source of truth.
        """

    # -- auth -----------------------------------------------------------

    def get_secret(self) -> str | None:
        """Return the API key, if configured. Subclasses override as needed.

        The default implementation reads ``metadata.auth.secret_name`` from
        the keyring; adapters can override for non-keyring sources.
        """
        return self._read_keyring_secret(self._metadata.auth.secret_name)

    @staticmethod
    def _read_keyring_secret(name: str | None) -> str | None:
        if not name:
            return None
        try:
            import keyring

            value = keyring.get_password("mavr", name)
            return value
        except Exception:  # noqa: BLE001 — keyring failures are non-fatal at probe time
            return None

    def auth_status(self) -> _AuthStatusStr:
        if not self._metadata.auth.required:
            return "ok"
        secret = self.get_secret()
        if secret is None or not secret.strip():
            return "missing"
        return "ok"

    # -- primary operations -------------------------------------------

    @abc.abstractmethod
    async def chat(self, model_key: str, request: ChatRequest) -> ChatResponse:
        """Send a chat completion request and return the response."""

    @abc.abstractmethod
    def stream(
        self, model_key: str, request: ChatRequest
    ) -> AsyncGenerator[ChatStream, None]:
        r"""Stream a chat completion, yielding chunks as they arrive.

        Subclasses implement this as an ``async def`` function that
        ``yield``\s :class:`ChatStream` chunks.
        """

    @abc.abstractmethod
    async def health(self) -> HealthReport:
        """Run a connectivity + auth probe. Never logs the secret.

        Implementations should return a structured report; the registry
        surfaces it to the CLI / UI.
        """

    # -- helpers -------------------------------------------------------

    def list_model_keys(self) -> list[str]:
        return [m.model_key for m in self.models()]

    def is_model_free(self, model_key: str) -> bool:
        for m in self.models():
            if m.model_key == model_key:
                return bool(m.free) and m.free_status == "confirmed"
        return False

    async def _with_timeout(self, awaitable, timeout: float):
        try:
            return await asyncio.wait_for(awaitable, timeout=timeout)
        except TimeoutError as exc:
            raise normalize_timeout_error(self.provider_id, str(exc)) from exc

    def __repr__(self) -> str:  # pragma: no cover — debug helper
        return f"<{type(self).__name__} provider_id={self.provider_id!r}>"
