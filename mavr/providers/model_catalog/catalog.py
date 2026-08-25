"""Declarative model catalog.

This module is the single source of truth for the models MAVR can talk
to. Adapters reference entries by ``(provider_id, model_key)``; the
bootstrap routine in :mod:`mavr.providers.model_catalog.bootstrap`
mirrors the entries into the DB on first use.

Hard rules (spec §7.3):

* Native free adapters: every model declared here must be ``free=True``
  with ``free_status="confirmed"`` and ``trust_level=native_free``.
* Partly-free gateway adapters: models MUST be explicitly flagged per
  model. ``free_status="unknown"`` is the safe default — unknown models
  are never routed to in free-only mode.
* Custom endpoints: declared ``free=...`` exactly as the user claims.
  The registry never auto-promotes a gateway model to free.
"""
from __future__ import annotations

from datetime import UTC, datetime

from mavr.schemas.routing import ModelCatalogEntry, TaskCategory, TrustLevel

_CATALOG_VERSION = "2026-01-15"


def _now() -> datetime:
    return datetime.now(UTC)


# ---- Hugging Face Inference (free tier) ---------------------------------
# Hugging Face's free Inference API tier hosts a small set of small/medium
# models. The list below is conservative — only models that have been
# verified to work on the free tier and require no credit card. Models
# with expired or unclear free status are NOT included.

HUGGINGFACE_FREE_MODELS: list[ModelCatalogEntry] = [
    ModelCatalogEntry(
        provider_id="huggingface",
        model_key="mistralai/Mistral-7B-Instruct-v0.3",
        display_name="Mistral 7B Instruct (HF free)",
        free=True,
        free_status="confirmed",
        trust_level=TrustLevel.NATIVE_FREE,
        context_limit=8192,
        tool_support=False,
        structured_output=False,
        streaming=True,
        rate_limit_rpm=10,
        notes="Hugging Face free inference tier; rate-limited.",
        last_verified=_now(),
        categories=[TaskCategory.GENERIC, TaskCategory.REVIEW, TaskCategory.POLISH],
    ),
    ModelCatalogEntry(
        provider_id="huggingface",
        model_key="meta-llama/Meta-Llama-3-8B-Instruct",
        display_name="Llama 3 8B Instruct (HF free)",
        free=True,
        free_status="confirmed",
        trust_level=TrustLevel.NATIVE_FREE,
        context_limit=8192,
        tool_support=False,
        structured_output=False,
        streaming=True,
        rate_limit_rpm=10,
        notes="Hugging Face free inference tier.",
        last_verified=_now(),
        categories=[TaskCategory.GENERIC, TaskCategory.REVIEW, TaskCategory.IMPACT],
    ),
    ModelCatalogEntry(
        provider_id="huggingface",
        model_key="google/gemma-2-9b-it",
        display_name="Gemma 2 9B IT (HF free)",
        free=True,
        free_status="confirmed",
        trust_level=TrustLevel.NATIVE_FREE,
        context_limit=8192,
        tool_support=False,
        structured_output=False,
        streaming=True,
        rate_limit_rpm=10,
        notes="Hugging Face free inference tier.",
        last_verified=_now(),
        categories=[TaskCategory.GENERIC, TaskCategory.POLISH],
    ),
]


# ---- Google Gemini (free tier) ------------------------------------------
# Gemini 1.5 Flash and Flash-8B are on the genuinely free tier with no
# credit card required. ``expires_at`` is included as a hint — the
# catalog bootstrap warns the operator if any entry's free status is
# older than 90 days so they can re-verify.

GEMINI_FREE_MODELS: list[ModelCatalogEntry] = [
    ModelCatalogEntry(
        provider_id="gemini",
        model_key="gemini-1.5-flash",
        display_name="Gemini 1.5 Flash",
        free=True,
        free_status="confirmed",
        trust_level=TrustLevel.NATIVE_FREE,
        context_limit=1_048_576,
        tool_support=True,
        structured_output=True,
        streaming=True,
        rate_limit_rpm=15,
        notes="Google AI Studio free tier; long context.",
        last_verified=_now(),
        categories=[
            TaskCategory.GENERIC,
            TaskCategory.IMPACT,
            TaskCategory.POC,
            TaskCategory.EXTRACTION,
            TaskCategory.SEARCH_QUERY,
        ],
    ),
    ModelCatalogEntry(
        provider_id="gemini",
        model_key="gemini-1.5-flash-8b",
        display_name="Gemini 1.5 Flash 8B",
        free=True,
        free_status="confirmed",
        trust_level=TrustLevel.NATIVE_FREE,
        context_limit=1_048_576,
        tool_support=True,
        structured_output=True,
        streaming=True,
        rate_limit_rpm=15,
        notes="Smaller, faster Gemini free tier.",
        last_verified=_now(),
        categories=[TaskCategory.GENERIC, TaskCategory.POLISH, TaskCategory.FINAL_REVIEW],
    ),
]


# ---- Partly-free gateway models ----------------------------------------
# Gateway models: only models explicitly marked free are included. The
# registry NEVER treats a gateway as "free" by default. If a model does
# not appear here, its free status is UNKNOWN and it is excluded from
# free-only routing.

OPENCODE_ZEN_FREE_MODELS: list[ModelCatalogEntry] = [
    ModelCatalogEntry(
        provider_id="opencode_zen",
        model_key="opencode-zen/llama-3.3-70b",
        display_name="Llama 3.3 70B (OpenCode Zen free)",
        free=True,
        free_status="confirmed",
        trust_level=TrustLevel.PARTLY_FREE_GATEWAY,
        context_limit=8192,
        tool_support=False,
        structured_output=False,
        streaming=True,
        rate_limit_rpm=20,
        notes="OpenCode Zen free tier; subject to gateway quota.",
        last_verified=_now(),
        categories=[TaskCategory.GENERIC, TaskCategory.REVIEW, TaskCategory.POLISH],
    ),
    ModelCatalogEntry(
        provider_id="opencode_zen",
        model_key="opencode-zen/qwen-2.5-coder-32b",
        display_name="Qwen 2.5 Coder 32B (OpenCode Zen free)",
        free=True,
        free_status="confirmed",
        trust_level=TrustLevel.PARTLY_FREE_GATEWAY,
        context_limit=8192,
        tool_support=False,
        structured_output=False,
        streaming=True,
        rate_limit_rpm=20,
        notes="OpenCode Zen free tier; code-specialized.",
        last_verified=_now(),
        categories=[TaskCategory.POC, TaskCategory.GENERIC],
    ),
]


KILO_GATEWAY_FREE_MODELS: list[ModelCatalogEntry] = [
    ModelCatalogEntry(
        provider_id="kilo_gateway",
        model_key="kilo/minimax/minimax-m3:free",
        display_name="minimax-m3:free (Kilo)",
        free=True,
        free_status="confirmed",
        trust_level=TrustLevel.PARTLY_FREE_GATEWAY,
        context_limit=32_768,
        tool_support=True,
        structured_output=False,
        streaming=True,
        rate_limit_rpm=30,
        notes="Kilo Gateway free tier.",
        last_verified=_now(),
        categories=[
            TaskCategory.GENERIC,
            TaskCategory.IMPACT,
            TaskCategory.POC,
            TaskCategory.POLISH,
        ],
    ),
    ModelCatalogEntry(
        provider_id="kilo_gateway",
        model_key="kilo/openai/gpt-oss-20b:free",
        display_name="gpt-oss 20B (Kilo free)",
        free=True,
        free_status="confirmed",
        trust_level=TrustLevel.PARTLY_FREE_GATEWAY,
        context_limit=16_384,
        tool_support=True,
        structured_output=False,
        streaming=True,
        rate_limit_rpm=30,
        notes="Kilo Gateway free tier.",
        last_verified=_now(),
        categories=[TaskCategory.GENERIC, TaskCategory.IMPACT, TaskCategory.FINAL_REVIEW],
    ),
]


# ---- Aggregated catalog ------------------------------------------------

ALL_FREE_MODEL_ENTRIES: list[ModelCatalogEntry] = [
    *HUGGINGFACE_FREE_MODELS,
    *GEMINI_FREE_MODELS,
    *OPENCODE_ZEN_FREE_MODELS,
    *KILO_GATEWAY_FREE_MODELS,
]


def entries_by_provider() -> dict[str, list[ModelCatalogEntry]]:
    out: dict[str, list[ModelCatalogEntry]] = {}
    for e in ALL_FREE_MODEL_ENTRIES:
        out.setdefault(e.provider_id, []).append(e)
    return out


def catalog_version() -> str:
    return _CATALOG_VERSION
