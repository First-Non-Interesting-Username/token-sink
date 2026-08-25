"""Provider subsystem: adapters, model catalog, registry."""
from __future__ import annotations

from mavr.providers.adapters.base import (
    AdapterAuth,
    AdapterMetadata,
    ChatStream,
    ProviderAdapter,
    normalize_http_error,
    normalize_timeout_error,
)
from mavr.providers.registry import ProviderRegistry, ProviderSummary

__all__ = [
    "AdapterAuth",
    "AdapterMetadata",
    "ChatStream",
    "ProviderAdapter",
    "ProviderRegistry",
    "ProviderSummary",
    "normalize_http_error",
    "normalize_timeout_error",
]
