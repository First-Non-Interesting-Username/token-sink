"""Tests for the provider adapter contract.

The contract: every adapter must expose ``models()``, ``chat()``,
``stream()``, ``health()``, and ``is_model_free()``; ``chat()`` must
return a :class:`ChatResponse` with a non-empty content; ``health()``
must not raise; auth must be reported without leaking the secret.
"""
from __future__ import annotations

import asyncio

import pytest

from mavr.providers.adapters.base import (
    ChatStream,
    normalize_http_error,
    normalize_timeout_error,
)
from mavr.providers.adapters.gemini import GeminiAdapter
from mavr.providers.adapters.huggingface import HuggingFaceAdapter
from mavr.providers.adapters.kilo_gateway import make_kilo_gateway_adapter
from mavr.providers.adapters.opencode_zen import make_opencode_zen_adapter
from mavr.schemas.routing import (
    ChatRequest,
    ChatResponse,
    ProviderErrorReason,
    TrustLevel,
)
from mavr.tests._fakes import MockAdapter


def test_mock_adapter_implements_contract() -> None:
    a = MockAdapter()
    # models
    models = a.models()
    assert models, "models() must return a non-empty list"
    for m in models:
        assert m.provider_id == "mock"
        assert m.free_status == "confirmed"
        assert m.free is True
    # free lookup
    assert a.is_model_free("mock-review") is True
    assert a.is_model_free("nope") is False
    # auth
    assert a.auth_status() == "ok"


@pytest.mark.asyncio
async def test_mock_adapter_chat_returns_content() -> None:
    a = MockAdapter()
    req = ChatRequest(messages=[{"role": "user", "content": "hi"}])  # type: ignore[list-item]
    resp = await a.chat("mock-review", req)
    assert isinstance(resp, ChatResponse)
    assert resp.content
    assert resp.finish_reason in {"stop", "length", "tool_call", "error", "cancelled"}


@pytest.mark.asyncio
async def test_mock_adapter_stream_yields_chunk() -> None:
    a = MockAdapter()
    req = ChatRequest(messages=[{"role": "user", "content": "hi"}])  # type: ignore[list-item]
    chunks: list[ChatStream] = []

    async def _drain() -> None:
        async for c in a.stream("mock-review", req):
            chunks.append(c)

    await asyncio.wait_for(_drain(), timeout=2.0)
    assert chunks, "stream() must yield at least one chunk"
    assert chunks[-1].content


@pytest.mark.asyncio
async def test_mock_adapter_health_reports_ok() -> None:
    a = MockAdapter()
    report = await a.health()
    assert report.ok is True
    assert report.auth_status == "ok"
    assert "mock" in report.detail.lower()


def test_normalize_http_error_classifies_status_codes() -> None:
    assert normalize_http_error(provider_id="p", http_status=401, message="x").reason == ProviderErrorReason.AUTH
    assert normalize_http_error(provider_id="p", http_status=403, message="x").reason == ProviderErrorReason.AUTH
    assert normalize_http_error(provider_id="p", http_status=429, message="x").reason == ProviderErrorReason.RATE_LIMIT
    assert normalize_http_error(provider_id="p", http_status=500, message="x").reason == ProviderErrorReason.OVERLOADED
    assert normalize_http_error(provider_id="p", http_status=408, message="x").reason == ProviderErrorReason.OVERLOADED
    assert normalize_http_error(provider_id="p", http_status=400, message="x").reason == ProviderErrorReason.MODEL_ERROR
    assert normalize_http_error(provider_id="p", http_status=None, message="x").reason == ProviderErrorReason.NETWORK
    # retryable flags
    assert normalize_http_error(provider_id="p", http_status=429, message="x").retryable is True
    assert normalize_http_error(provider_id="p", http_status=401, message="x").retryable is False


def test_normalize_timeout_error_is_retryable() -> None:
    err = normalize_timeout_error("p", "boom")
    assert err.reason == ProviderErrorReason.TIMEOUT
    assert err.retryable is True


def test_adapter_metadata_does_not_carry_secret() -> None:
    a = MockAdapter()
    md = a.metadata
    # repr/str of the metadata must never include the secret value.
    assert "mock-secret" not in repr(md)
    assert "mock-secret" not in str(md)


def test_huggingface_lists_only_free_models() -> None:
    a = HuggingFaceAdapter()
    models = a.models()
    assert models
    for m in models:
        assert m.free is True
        assert m.free_status == "confirmed"
        assert m.trust_level == TrustLevel.NATIVE_FREE


def test_gemini_lists_only_free_models() -> None:
    a = GeminiAdapter()
    models = a.models()
    assert models
    for m in models:
        assert m.free is True
        assert m.free_status == "confirmed"
        assert m.trust_level == TrustLevel.NATIVE_FREE


def test_opencode_zen_gateway_models_are_free() -> None:
    a = make_opencode_zen_adapter()
    models = a.models()
    assert models
    for m in models:
        assert m.trust_level == TrustLevel.PARTLY_FREE_GATEWAY
        assert m.free is True
        assert m.free_status == "confirmed"


def test_kilo_gateway_models_are_free() -> None:
    a = make_kilo_gateway_adapter()
    models = a.models()
    assert models
    for m in models:
        assert m.trust_level == TrustLevel.PARTLY_FREE_GATEWAY
        assert m.free is True
        assert m.free_status == "confirmed"


@pytest.mark.asyncio
async def test_custom_endpoint_adapter_basic() -> None:
    from mavr.providers.adapters.custom import build_custom_endpoint_adapter

    a = build_custom_endpoint_adapter(
        provider_id="my_custom",
        base_url="https://example.com/v1",
        model_keys=["custom-model"],
        free=False,
        free_status="paid",
        auth_secret_name=None,
        auth_required=False,
    )
    assert a.provider_id == "my_custom"
    models = a.models()
    assert len(models) == 1
    assert models[0].free is False
    assert models[0].free_status == "paid"


def test_custom_endpoint_validates_url() -> None:
    from mavr.providers.adapters.custom import parse_custom_endpoint_config

    with pytest.raises(ValueError, match="must start with"):
        parse_custom_endpoint_config(
            {
                "provider_id": "p",
                "base_url": "ftp://x",
                "model_keys": ["m"],
            }
        )
    with pytest.raises(ValueError, match="must not contain credentials"):
        parse_custom_endpoint_config(
            {
                "provider_id": "p",
                "base_url": "https://user:pass@host",
                "model_keys": ["m"],
            }
        )
    with pytest.raises(ValueError, match="non-empty list"):
        parse_custom_endpoint_config(
            {
                "provider_id": "p",
                "base_url": "https://h",
                "model_keys": [],
            }
        )
