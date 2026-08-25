"""Provider registry.

The registry is the in-process index of every adapter MAVR can talk to.
It exposes:

* :meth:`list` — summary of every registered provider
* :meth:`get` — adapter by ``provider_id``
* :meth:`health_all` — run a connectivity probe against every adapter
* :meth:`bootstrap_catalog` — mirror the model catalog into the DB

Secrets are never logged. The registry only surfaces ``auth_status``
(``ok | missing | invalid``); the secret value itself stays in the
keyring.
"""
from __future__ import annotations

import asyncio
from collections.abc import Iterable
from dataclasses import dataclass

import httpx

from mavr.observability.logging import get_logger
from mavr.providers.adapters.base import ProviderAdapter
from mavr.providers.adapters.custom import build_custom_endpoint_adapter
from mavr.providers.adapters.gemini import GeminiAdapter
from mavr.providers.adapters.huggingface import HuggingFaceAdapter
from mavr.providers.adapters.kilo_gateway import make_kilo_gateway_adapter
from mavr.providers.adapters.opencode_zen import make_opencode_zen_adapter
from mavr.providers.model_catalog.bootstrap import CatalogBootstrapper
from mavr.schemas.routing import HealthReport
from mavr.storage.database import Database

log = get_logger(__name__)


@dataclass(frozen=True)
class ProviderSummary:
    provider_id: str
    display_name: str
    kind: str
    free: bool
    auth_status: str
    model_count: int
    base_url: str | None = None


class ProviderRegistry:
    def __init__(
        self,
        adapters: Iterable[ProviderAdapter] | None = None,
        *,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        self._adapters: dict[str, ProviderAdapter] = {}
        self._http = http_client
        self._owns_http = http_client is None
        for a in adapters or ():
            self.register(a)
        if self._http is None:
            self._http = httpx.AsyncClient(timeout=httpx.Timeout(60.0))

    # -- construction helpers ----------------------------------------

    @classmethod
    def default(
        cls, *, http_client: httpx.AsyncClient | None = None
    ) -> ProviderRegistry:
        """Build the default registry with the four built-in adapters."""
        client = http_client or httpx.AsyncClient(timeout=httpx.Timeout(60.0))
        return cls(
            [
                HuggingFaceAdapter(client=client),
                GeminiAdapter(client=client),
                make_opencode_zen_adapter(client=client),
                make_kilo_gateway_adapter(client=client),
            ],
            http_client=client,
        )

    # -- registration ------------------------------------------------

    def register(self, adapter: ProviderAdapter) -> None:
        pid = adapter.provider_id
        if pid in self._adapters:
            log.warning("registry_overwrite", provider_id=pid)
        self._adapters[pid] = adapter

    def add_custom(self, **kwargs) -> ProviderAdapter:
        adapter = build_custom_endpoint_adapter(client=self._http, **kwargs)
        self.register(adapter)
        return adapter

    # -- queries -----------------------------------------------------

    def list(self) -> list[ProviderSummary]:
        return [
            ProviderSummary(
                provider_id=a.provider_id,
                display_name=a.metadata.display_name,
                kind=a.metadata.kind,
                free=any(m.free and m.free_status == "confirmed" for m in a.models()),
                auth_status=a.auth_status(),
                model_count=len(a.list_model_keys()),
                base_url=a.metadata.base_url,
            )
            for a in self._adapters.values()
        ]

    def get(self, provider_id: str) -> ProviderAdapter:
        try:
            return self._adapters[provider_id]
        except KeyError as exc:
            raise KeyError(f"unknown provider_id: {provider_id!r}") from exc

    def has(self, provider_id: str) -> bool:
        return provider_id in self._adapters

    def all(self) -> list[ProviderAdapter]:  # type: ignore[valid-type]
        return list(self._adapters.values())

    def free_models(self) -> list[tuple[ProviderAdapter, str]]:  # type: ignore[valid-type]
        out: list[tuple[ProviderAdapter, str]] = []
        for a in self._adapters.values():
            for m in a.models():
                if m.free and m.free_status == "confirmed":
                    out.append((a, m.model_key))
        return out

    # -- health ------------------------------------------------------

    async def health_all(
        self, *, timeout: float = 5.0
    ) -> list[tuple[str, HealthReport]]:  # type: ignore[valid-type]
        results: list[tuple[str, HealthReport]] = []
        coros = [self._health_one(pid, a, timeout) for pid, a in self._adapters.items()]
        for pair in await asyncio.gather(*coros, return_exceptions=True):
            if isinstance(pair, BaseException):
                continue
            results.append(pair)
        return results

    async def health(self, provider_id: str) -> HealthReport:
        return await self.get(provider_id).health()

    async def _health_one(
        self, provider_id: str, adapter: ProviderAdapter, timeout: float
    ) -> tuple[str, HealthReport]:
        try:
            report = await asyncio.wait_for(adapter.health(), timeout=timeout)
        except Exception as exc:  # noqa: BLE001
            return provider_id, HealthReport(ok=False, auth_status=adapter.auth_status(), detail=str(exc))
        return provider_id, report

    # -- bootstrap ---------------------------------------------------

    async def bootstrap_catalog(self, db: Database) -> int:
        bootstrapper = CatalogBootstrapper(db)
        return await bootstrapper.run()

    # -- lifecycle ---------------------------------------------------

    async def aclose(self) -> None:
        if self._owns_http and self._http is not None:
            await self._http.aclose()
            self._http = None
