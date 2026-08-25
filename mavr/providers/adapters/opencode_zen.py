"""OpenCode Zen partly-free gateway adapter.

The OpenCode Zen gateway exposes a free tier for a small, curated set
of models. Free status is **per model** — models not listed in
:mod:`mavr.providers.model_catalog.catalog` are treated as ``unknown``
and excluded from free-only routing. This adapter never assumes a
gateway model is free just because the gateway is partly free.
"""
from __future__ import annotations

import httpx

from mavr.providers.adapters.openai_compat import OpenAICompatibleAdapter
from mavr.providers.model_catalog.catalog import OPENCODE_ZEN_FREE_MODELS
from mavr.schemas.routing import AdapterCapabilities

PROVIDER_ID = "opencode_zen"
DEFAULT_BASE = "https://api.opencode.ai/v1"


def make_opencode_zen_adapter(
    *, client: httpx.AsyncClient | None = None
) -> OpenAICompatibleAdapter:
    return OpenAICompatibleAdapter(
        provider_id=PROVIDER_ID,
        display_name="OpenCode Zen (partly free)",
        kind="gateway",
        base_url=DEFAULT_BASE,
        auth_secret_name="OPENCODE_ZEN_API_KEY",
        models=list(OPENCODE_ZEN_FREE_MODELS),
        capabilities=AdapterCapabilities(
            streaming=True,
            tool_support=False,
            structured_output=False,
            rate_limit_rpm=20,
            request_timeout_seconds=60.0,
        ),
        auth_required=True,
        client=client,
    )
