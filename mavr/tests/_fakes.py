"""In-process test fakes shared across the suite."""
from __future__ import annotations

from collections.abc import AsyncGenerator
from datetime import UTC, datetime

from mavr.providers.adapters.base import (
    AdapterAuth,
    AdapterMetadata,
    ChatStream,
    ProviderAdapter,
)
from mavr.schemas.routing import (
    AdapterCapabilities,
    ChatRequest,
    ChatResponse,
    HealthReport,
    ModelCatalogEntry,
    TaskCategory,
    TrustLevel,
    UsageInfo,
)


def _now() -> datetime:
    return datetime.now(UTC)


class MockAdapter(ProviderAdapter):
    """An adapter used by tests and the offline benchmark CLI.

    The catalog entries cover each task category and the ``chat`` method
    returns deterministic, checkable content. The model list is
    deliberately small so the benchmark remains fast.
    """

    PROVIDER_ID = "mock"

    def __init__(
        self,
        *,
        latency_ms: int = 1,
        responses: dict[str, str] | None = None,
        fail_on: set[str] | None = None,
    ) -> None:
        super().__init__(
            AdapterMetadata(
                provider_id=self.PROVIDER_ID,
                display_name="Mock adapter (in-process)",
                kind="native",
                capabilities=AdapterCapabilities(
                    streaming=True,
                    tool_support=False,
                    structured_output=True,
                    rate_limit_rpm=1000,
                    request_timeout_seconds=5.0,
                ),
                auth=AdapterAuth(secret_name=None, required=False),
            )
        )
        self._latency_ms = latency_ms
        self._responses = responses or {}
        self._fail_on = fail_on or set()

    def models(self) -> list[ModelCatalogEntry]:
        return [
            ModelCatalogEntry(
                provider_id=self.PROVIDER_ID,
                model_key="mock-review",
                display_name="Mock review model",
                free=True,
                free_status="confirmed",
                trust_level=TrustLevel.NATIVE_FREE,
                context_limit=8192,
                last_verified=_now(),
                categories=[TaskCategory.REVIEW, TaskCategory.GENERIC],
            ),
            ModelCatalogEntry(
                provider_id=self.PROVIDER_ID,
                model_key="mock-discovery",
                display_name="Mock discovery model",
                free=True,
                free_status="confirmed",
                trust_level=TrustLevel.NATIVE_FREE,
                context_limit=8192,
                last_verified=_now(),
                categories=[TaskCategory.DISCOVERY, TaskCategory.GENERIC],
            ),
            ModelCatalogEntry(
                provider_id=self.PROVIDER_ID,
                model_key="mock-polish",
                display_name="Mock polish model",
                free=True,
                free_status="confirmed",
                trust_level=TrustLevel.NATIVE_FREE,
                context_limit=8192,
                last_verified=_now(),
                categories=[TaskCategory.POLISH, TaskCategory.GENERIC],
            ),
        ]

    def get_secret(self) -> str | None:
        return "mock-secret"

    async def chat(self, model_key: str, request: ChatRequest) -> ChatResponse:
        if model_key in self._fail_on:
            from mavr.schemas.routing import ProviderError, ProviderErrorReason

            raise ProviderError(
                ProviderErrorReason.MODEL_ERROR,
                f"mock failure for {model_key}",
                retryable=True,
                provider_id=self.PROVIDER_ID,
            )
        if model_key in self._responses:
            return ChatResponse(
                content=self._responses[model_key],
                finish_reason="stop",
                usage=UsageInfo(input_tokens=10, output_tokens=20, is_free=True),
            )
        # Default response: echo the user message + a token the benchmark
        # prompt expects.
        user_msg = ""
        for m in request.messages:
            if m.role == "user":
                user_msg = m.content
                break
        return ChatResponse(
            content=f"echo: {user_msg[:64]} | accept | XSS SQL CSRF | vulnerability | yes | reject",
            finish_reason="stop",
            usage=UsageInfo(input_tokens=12, output_tokens=24, is_free=True),
        )

    async def stream(
        self, model_key: str, request: ChatRequest
    ) -> AsyncGenerator[ChatStream, None]:
        resp = await self.chat(model_key, request)
        yield ChatStream(content=resp.content, finish_reason=resp.finish_reason, usage=resp.usage)

    async def health(self) -> HealthReport:
        return HealthReport(ok=True, auth_status="ok", detail="mock-healthy")


class FlakyAdapter(ProviderAdapter):
    """Adapter that fails the first N times it is called, then succeeds."""

    def __init__(self, *, fail_first: int = 2) -> None:
        super().__init__(
            AdapterMetadata(
                provider_id="flaky",
                display_name="Flaky adapter",
                kind="native",
                capabilities=AdapterCapabilities(request_timeout_seconds=5.0),
                auth=AdapterAuth(secret_name=None, required=False),
            )
        )
        self._fail_first = fail_first
        self._calls = 0

    def models(self) -> list[ModelCatalogEntry]:
        return [
            ModelCatalogEntry(
                provider_id="flaky",
                model_key="flaky-model",
                display_name="Flaky model",
                free=True,
                free_status="confirmed",
                trust_level=TrustLevel.NATIVE_FREE,
                context_limit=4096,
                last_verified=_now(),
                categories=[TaskCategory.GENERIC],
            )
        ]

    def get_secret(self) -> str | None:
        return "flaky-secret"

    async def chat(self, model_key: str, request: ChatRequest) -> ChatResponse:
        self._calls += 1
        if self._calls <= self._fail_first:
            from mavr.schemas.routing import ProviderError, ProviderErrorReason

            raise ProviderError(
                ProviderErrorReason.OVERLOADED,
                f"flake {self._calls}",
                retryable=True,
                provider_id="flaky",
            )
        return ChatResponse(content="recovered", finish_reason="stop", usage=UsageInfo(is_free=True))

    async def stream(
        self, model_key: str, request: ChatRequest
    ) -> AsyncGenerator[ChatStream, None]:
        resp = await self.chat(model_key, request)
        yield ChatStream(content=resp.content, usage=resp.usage)

    async def health(self) -> HealthReport:
        return HealthReport(ok=True, auth_status="ok", detail="flaky")
