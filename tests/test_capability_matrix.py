"""Tests for the §8.1 capability matrix + conformance verification."""
from __future__ import annotations

import json

import httpx
import pytest

from mavr.providers.adapters.openai_compat import OpenAICompatibleAdapter
from mavr.providers.capability_matrix import (
    build_matrix,
    eligible_for_structured,
    verify_adapter,
)
from mavr.schemas.routing import AdapterCapabilities, ModelCatalogEntry, TrustLevel


def _entry(model_key: str) -> ModelCatalogEntry:
    return ModelCatalogEntry(
        provider_id="mock",
        model_key=model_key,
        display_name=model_key,
        free=True,
        free_status="confirmed",
        trust_level=TrustLevel.OPENAI_COMPAT,
        context_limit=4096,
    )


def _adapter(
    caps: AdapterCapabilities | None = None, base_url: str = "http://mock.local"
) -> OpenAICompatibleAdapter:
    return OpenAICompatibleAdapter(
        provider_id="mock",
        display_name="Mock",
        kind="openai_compat",
        base_url=base_url,
        auth_secret_name=None,
        models=[_entry("m1"), _entry("m2")],
        capabilities=caps or AdapterCapabilities(streaming=True),
        auth_required=False,
    )


# ---- matrix -------------------------------------------------------------


def test_build_matrix_rows_per_model() -> None:
    a = _adapter(AdapterCapabilities(streaming=True, structured_output=True))
    rows = build_matrix([a])
    assert len(rows) == 2
    assert all(r.streaming and r.structured_output and not r.tool_support for r in rows)
    assert {r.model_key for r in rows} == {"m1", "m2"}


# ---- conformance verification --------------------------------------------


@pytest.mark.asyncio
async def test_verify_streaming_ok() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        if body.get("stream"):
            payload = (
                'data: {"choices":[{"delta":{"content":"ok"}}]}\n\n'
                'data: [DONE]\n\n'
            )
            return httpx.Response(
                200, content=payload.encode(), headers={"content-type": "text/event-stream"}
            )
        return httpx.Response(
            200,
            json={"choices": [{"message": {"content": "ok"}, "finish_reason": "stop"}]},
        )

    transport = httpx.MockTransport(handler)
    a = _adapter(
        AdapterCapabilities(streaming=True, structured_output=False),
        base_url="http://mock",
    )
    a._client = httpx.AsyncClient(transport=transport)
    result = await verify_adapter(a)
    assert result["declared"]["streaming"] is True
    assert result["verified"]["streaming"] is True


@pytest.mark.asyncio
async def test_verify_structured_output_non_json_flagged() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={"choices": [{"message": {"content": "not json at all"}, "finish_reason": "stop"}]},
        )

    a = _adapter(
        AdapterCapabilities(structured_output=True),
        base_url="http://mock",
    )
    a._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    result = await verify_adapter(a)
    assert result["declared"]["structured_output"] is True
    assert result["verified"]["structured_output"] is False
    assert any("non-JSON" in n for n in result["notes"])


@pytest.mark.asyncio
async def test_verify_probe_failure_is_data_not_error() -> None:
    a = _adapter(
        AdapterCapabilities(streaming=True, structured_output=True),
        base_url="http://unreachable.invalid",
    )
    # No transport swap — real client against an unreachable host.
    result = await verify_adapter(a)
    assert result["verified"]["streaming"] is False
    assert any("failed" in n for n in result["notes"])


def test_verify_no_models_reports_all_unverified() -> None:
    from mavr.schemas.routing import AdapterCapabilities as Caps

    class EmptyAdapter(OpenAICompatibleAdapter):
        pass

    a = EmptyAdapter(
        provider_id="empty",
        display_name="Empty",
        kind="openai_compat",
        base_url="http://mock",
        auth_secret_name=None,
        models=[],
        capabilities=Caps(streaming=True),
        auth_required=False,
    )
    import asyncio

    res = asyncio.run(verify_adapter(a))
    assert all(v is False for v in res["verified"].values())
    assert res["notes"] == ["no models registered"]


# ---- routing enforcement -------------------------------------------------


def test_eligible_with_verified_capability() -> None:
    e = eligible_for_structured(capabilities_verified={"structured_output": True})
    assert e.eligible and not e.fallback


def test_ineligible_without_fallback() -> None:
    e = eligible_for_structured(capabilities_verified={"structured_output": False})
    assert not e.eligible


def test_fallback_allowed_when_explicit() -> None:
    e = eligible_for_structured(
        capabilities_verified={"structured_output": False}, allow_json_fallback=True
    )
    assert e.eligible and e.fallback
