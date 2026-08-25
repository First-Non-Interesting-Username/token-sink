"""Tests for the free-only filter, the gateway filter, and the registry."""
from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime  # noqa: F811

import pytest

from mavr.providers.adapters.base import (
    AdapterMetadata,
    ChatStream,
    ProviderAdapter,
)
from mavr.providers.adapters.custom import (
    build_custom_endpoint_adapter,
    parse_custom_endpoint_config,
)
from mavr.providers.registry import ProviderRegistry
from mavr.routers.free_filter import (
    FreeOnlyViolation,
    eligible_candidates,
    require_paid_override,
)
from mavr.schemas.routing import (
    ChatRequest,
    ChatResponse,
    HealthReport,
    ModelCatalogEntry,
    TaskCategory,
    TrustLevel,
    UsageInfo,
)
from mavr.tests._fakes import MockAdapter


def _now() -> datetime:
    return datetime.now(UTC)


# ---- free-only filter ---------------------------------------------------


def _entry(*, free: bool, free_status: str) -> ModelCatalogEntry:
    return ModelCatalogEntry(
        provider_id="test_provider",
        model_key="test-model",
        display_name="m",
        free=free,
        free_status=free_status,  # type: ignore[arg-type]
        trust_level=TrustLevel.NATIVE_FREE,
        context_limit=4096,
        last_verified=_now(),
        categories=[TaskCategory.GENERIC],
    )


def test_free_only_filter_accepts_confirmed_free() -> None:
    e = _entry(free=True, free_status="confirmed")
    out = eligible_candidates(e, free_only=True)
    assert out is e


def test_free_only_filter_rejects_unknown() -> None:
    with pytest.raises(FreeOnlyViolation):
        eligible_candidates(_entry(free=False, free_status="unknown"), free_only=True)


def test_free_only_filter_rejects_paid() -> None:
    with pytest.raises(FreeOnlyViolation):
        eligible_candidates(_entry(free=False, free_status="paid"), free_only=True)


def test_free_only_filter_paid_override_requires_human_approval() -> None:
    e = _entry(free=False, free_status="paid")
    # override without human_approved: still rejected
    with pytest.raises(FreeOnlyViolation):
        eligible_candidates(e, free_only=True, allow_paid_override=True, human_approved=False)
    # override with both flags: accepted
    out = eligible_candidates(e, free_only=True, allow_paid_override=True, human_approved=True)
    assert out is e


def test_require_paid_override_logic() -> None:
    class _T:
        free_only = True
        allow_paid_override = False
        human_approved = False

    assert require_paid_override(_T()) is False
    _T.allow_paid_override = True
    assert require_paid_override(_T()) is False
    _T.human_approved = True
    assert require_paid_override(_T()) is True
    _T.free_only = False
    assert require_paid_override(_T()) is True


# ---- gateway filter: unmarked models are unknown ------------------------


def test_gateway_filter_rejects_unmarked_models() -> None:
    """A model that's not in the gateway's free list must be treated as unknown.

    The gateway adapter declares its free model list explicitly. Any
    model the user wants to add must go through the explicit
    ``build_custom_endpoint_adapter`` path. The registry never
    auto-promotes a gateway model to free.
    """

    class GatewayOnlyAdapter(ProviderAdapter):
        def __init__(self) -> None:
            super().__init__(
                AdapterMetadata(
                    provider_id="partial",
                    display_name="Partial gateway",
                    kind="gateway",
                )
            )

        def models(self) -> list[ModelCatalogEntry]:
            return [
                _entry(free=True, free_status="confirmed").model_copy(
                    update={"provider_id": "partial", "model_key": "free-one"}
                )
            ]

        async def chat(self, model_key: str, request: ChatRequest) -> ChatResponse:
            return ChatResponse(content="ok", usage=UsageInfo(is_free=True))

        async def stream(self, model_key: str, request: ChatRequest) -> AsyncIterator[ChatStream]:
            yield ChatStream(content="ok")

        async def health(self) -> HealthReport:
            return HealthReport(ok=True, auth_status="ok")

    gw = GatewayOnlyAdapter()
    assert gw.is_model_free("free-one") is True
    assert gw.is_model_free("not-listed") is False
    # trying to filter a non-listed model through free-only must raise
    other = _entry(free=False, free_status="unknown").model_copy(
        update={"provider_id": "partial", "model_key": "not-listed"}
    )
    with pytest.raises(FreeOnlyViolation):
        eligible_candidates(other, free_only=True)


# ---- registry -----------------------------------------------------------


@pytest.mark.asyncio
async def test_registry_lists_adapters() -> None:
    reg = ProviderRegistry([MockAdapter()])
    summaries = reg.list()
    assert len(summaries) == 1
    assert summaries[0].provider_id == "mock"
    assert summaries[0].free is True
    assert summaries[0].model_count == 3


@pytest.mark.asyncio
async def test_registry_get_unknown_raises() -> None:
    reg = ProviderRegistry()
    with pytest.raises(KeyError):
        reg.get("nope")


@pytest.mark.asyncio
async def test_registry_health_all_returns_reports() -> None:
    reg = ProviderRegistry([MockAdapter()])
    results = await reg.health_all()
    assert results
    for pid, report in results:
        assert pid == "mock"
        assert report.ok is True


@pytest.mark.asyncio
async def test_registry_aclose_is_idempotent() -> None:
    reg = ProviderRegistry([MockAdapter()])
    await reg.aclose()
    await reg.aclose()


def test_registry_default_has_four_providers() -> None:
    """The default registry wires up HF, Gemini, OpenCode Zen, Kilo Gateway."""
    reg = ProviderRegistry.default()
    pids = {s.provider_id for s in reg.list()}
    assert {"huggingface", "gemini", "opencode_zen", "kilo_gateway"} <= pids


def test_custom_endpoint_adapter_is_paid_only_by_default() -> None:
    """A custom endpoint without explicit free=True must be paid by default."""
    spec = parse_custom_endpoint_config(
        {
            "provider_id": "my_local",
            "base_url": "http://localhost:8080/v1",
            "model_keys": ["llama-3"],
            "auth_secret_name": None,
            "auth_required": False,
        }
    )
    a = build_custom_endpoint_adapter(**spec)
    models = a.models()
    assert models[0].free is False
    assert models[0].free_status == "unknown"
