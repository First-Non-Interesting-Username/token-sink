"""Model catalog: declarative entries, scoring, and DB bootstrap."""
from __future__ import annotations

from mavr.providers.model_catalog.bootstrap import CatalogBootstrapper
from mavr.providers.model_catalog.catalog import (
    ALL_FREE_MODEL_ENTRIES,
    GEMINI_FREE_MODELS,
    HUGGINGFACE_FREE_MODELS,
    KILO_GATEWAY_FREE_MODELS,
    OPENCODE_ZEN_FREE_MODELS,
    catalog_version,
    entries_by_provider,
)
from mavr.providers.model_catalog.scores import ModelScoreStore

__all__ = [
    "ALL_FREE_MODEL_ENTRIES",
    "CatalogBootstrapper",
    "GEMINI_FREE_MODELS",
    "HUGGINGFACE_FREE_MODELS",
    "KILO_GATEWAY_FREE_MODELS",
    "ModelScoreStore",
    "OPENCODE_ZEN_FREE_MODELS",
    "catalog_version",
    "entries_by_provider",
]
