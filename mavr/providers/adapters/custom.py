"""Custom user-supplied OpenAI-compatible endpoint support.

The user provides a base URL, a list of model keys, capabilities, and
the free/paid classification. The free/paid flag is the user's claim;
the router enforces ``free_only`` against the per-model free flag from
this factory. We never re-classify a user-supplied model as free
without an explicit ``free=True`` from the user.
"""
from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import httpx

from mavr.providers.adapters.openai_compat import OpenAICompatibleAdapter
from mavr.schemas.routing import (
    AdapterCapabilities,
    ModelCatalogEntry,
    TaskCategory,
    TrustLevel,
)


def _now() -> datetime:
    return datetime.now(UTC)


def build_custom_endpoint_adapter(
    *,
    provider_id: str,
    base_url: str,
    model_keys: list[str],
    free: bool,
    free_status: str,
    auth_secret_name: str | None,
    auth_required: bool = True,
    capabilities: AdapterCapabilities | None = None,
    context_limit: int = 8192,
    rate_limit_rpm: int | None = None,
    categories: list[TaskCategory] | None = None,
    notes: str = "",
    client: httpx.AsyncClient | None = None,
    extra_headers: dict[str, str] | None = None,
) -> OpenAICompatibleAdapter:
    """Build an adapter for a user-supplied OpenAI-compatible endpoint.

    The caller is responsible for validating the URL (no private
    networks, https preferred, no embedded secrets in the URL).
    """
    if not model_keys:
        raise ValueError("at least one model_key is required for a custom endpoint")
    if free_status not in {"confirmed", "unknown", "paid"}:
        raise ValueError(f"free_status must be one of confirmed|unknown|paid (got {free_status!r})")
    if not free and free_status == "confirmed":
        raise ValueError("free=False with free_status='confirmed' is contradictory")

    entries: list[ModelCatalogEntry] = []
    for key in model_keys:
        entries.append(
            ModelCatalogEntry(
                provider_id=provider_id,
                model_key=key,
                display_name=key,
                free=free,
                free_status=free_status,  # type: ignore[arg-type]
                trust_level=TrustLevel.OPENAI_COMPAT,
                context_limit=context_limit,
                tool_support=bool(capabilities and capabilities.tool_support),
                structured_output=bool(capabilities and capabilities.structured_output),
                streaming=bool(capabilities and capabilities.streaming),
                rate_limit_rpm=rate_limit_rpm,
                notes=notes,
                last_verified=_now(),
                categories=list(categories or []),
            )
        )
    return OpenAICompatibleAdapter(
        provider_id=provider_id,
        display_name=f"Custom endpoint ({provider_id})",
        kind="custom",
        base_url=base_url,
        auth_secret_name=auth_secret_name,
        models=entries,
        capabilities=capabilities
        or AdapterCapabilities(
            streaming=True,
            tool_support=False,
            structured_output=False,
            rate_limit_rpm=rate_limit_rpm,
            request_timeout_seconds=60.0,
        ),
        auth_required=auth_required,
        client=client,
        extra_headers=extra_headers,
    )


def parse_custom_endpoint_config(payload: dict[str, Any]) -> dict[str, Any]:
    """Validate a user-supplied endpoint spec.

    Returns the validated spec as a plain dict. Raises ``ValueError`` on
    any invalid field. Does NOT log the secret.
    """
    if not isinstance(payload, dict):
        raise ValueError("custom endpoint config must be a mapping")
    required = {"provider_id", "base_url", "model_keys"}
    missing = required - payload.keys()
    if missing:
        raise ValueError(f"custom endpoint config missing keys: {sorted(missing)}")
    pid = str(payload["provider_id"]).strip()
    if not pid:
        raise ValueError("provider_id must not be empty")
    base_url = str(payload["base_url"]).strip()
    if not base_url.startswith(("http://", "https://")):
        raise ValueError("base_url must start with http:// or https://")
    if any(c in base_url for c in ("@", " ")):
        raise ValueError("base_url must not contain credentials or whitespace")
    model_keys = payload["model_keys"]
    if not isinstance(model_keys, list) or not model_keys:
        raise ValueError("model_keys must be a non-empty list of strings")
    for k in model_keys:
        if not isinstance(k, str) or not k.strip():
            raise ValueError("every model_key must be a non-empty string")
    return {
        "provider_id": pid,
        "base_url": base_url,
        "model_keys": [str(k).strip() for k in model_keys],
        "free": bool(payload.get("free", False)),
        "free_status": str(payload.get("free_status", "unknown")),
        "auth_secret_name": payload.get("auth_secret_name"),
        "auth_required": bool(payload.get("auth_required", True)),
        "context_limit": int(payload.get("context_limit", 8192)),
        "rate_limit_rpm": payload.get("rate_limit_rpm"),
        "notes": str(payload.get("notes", "")),
        "categories": list(payload.get("categories", []) or []),
        "extra_headers": dict(payload.get("extra_headers", {}) or {}),
    }
