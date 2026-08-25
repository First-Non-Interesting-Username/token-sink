"""Kilo Gateway partly-free adapter.

Same strict per-model free filter as :mod:`mavr.providers.adapters.opencode_zen`.
"""
from __future__ import annotations

import httpx

from mavr.providers.adapters.openai_compat import OpenAICompatibleAdapter
from mavr.providers.model_catalog.catalog import KILO_GATEWAY_FREE_MODELS
from mavr.schemas.routing import AdapterCapabilities

PROVIDER_ID = "kilo_gateway"
DEFAULT_BASE = "https://api.kilo.ai/v1"


def make_kilo_gateway_adapter(
    *, client: httpx.AsyncClient | None = None
) -> OpenAICompatibleAdapter:
    return OpenAICompatibleAdapter(
        provider_id=PROVIDER_ID,
        display_name="Kilo Gateway (partly free)",
        kind="gateway",
        base_url=DEFAULT_BASE,
        auth_secret_name="KILO_API_KEY",
        models=list(KILO_GATEWAY_FREE_MODELS),
        capabilities=AdapterCapabilities(
            streaming=True,
            tool_support=True,
            structured_output=False,
            rate_limit_rpm=30,
            request_timeout_seconds=60.0,
        ),
        auth_required=True,
        client=client,
    )
