"""Bootstrap the model catalog into the DB.

This module is the only place that mutates the ``providers`` and
``models`` tables on cold start. It reads the declarative
:class:`mavr.providers.model_catalog.catalog` and writes the corresponding
rows. It is idempotent — re-running it does not produce duplicates and
preserves the ``last_verified`` timestamp on unchanged entries.
"""
from __future__ import annotations

from collections.abc import Iterable
from datetime import UTC, datetime
from uuid import uuid4

from mavr.observability.logging import get_logger
from mavr.providers.model_catalog.catalog import (
    ALL_FREE_MODEL_ENTRIES,
    catalog_version,
)
from mavr.schemas.entities import (
    SCHEMA_VERSION,
    AuthStatus,
    FreeStatus,
    ModelPricing,
    ProviderCapabilities,
    ProviderKind,
)
from mavr.schemas.routing import ModelCatalogEntry, TrustLevel
from mavr.storage.database import Database

log = get_logger(__name__)

_PROVIDER_KIND_BY_TRUST: dict[TrustLevel, ProviderKind] = {
    TrustLevel.NATIVE_FREE: ProviderKind.NATIVE,
    TrustLevel.PARTLY_FREE_GATEWAY: ProviderKind.GATEWAY,
    TrustLevel.OPENAI_COMPAT: ProviderKind.CUSTOM,
    TrustLevel.PAID_ONLY: ProviderKind.NATIVE,
}

_PROVIDER_DISPLAY: dict[str, str] = {
    "huggingface": "Hugging Face Inference",
    "gemini": "Google Gemini",
    "opencode_zen": "OpenCode Zen",
    "kilo_gateway": "Kilo Gateway",
}


class CatalogBootstrapper:
    def __init__(self, db: Database) -> None:
        self._db = db

    async def run(self, entries: Iterable[ModelCatalogEntry] | None = None) -> int:
        """Mirror the catalog into the DB. Returns the number of model rows written/updated."""
        items = list(entries) if entries is not None else list(ALL_FREE_MODEL_ENTRIES)
        # group by provider
        by_provider: dict[str, list[ModelCatalogEntry]] = {}
        for e in items:
            by_provider.setdefault(e.provider_id, []).append(e)

        written = 0
        now = _now_iso()
        for pid, group in by_provider.items():
            await self._upsert_provider(pid, group[0], now)
            for entry in group:
                await self._upsert_model(entry, now)
                written += 1
        log.info("catalog_bootstrap", version=catalog_version(), providers=len(by_provider), models=written)
        return written

    async def _upsert_provider(
        self, provider_id: str, sample: ModelCatalogEntry, now: str
    ) -> None:
        kind = _PROVIDER_KIND_BY_TRUST[sample.trust_level]
        existing = await self._db.fetchone(
            "SELECT id, created_at FROM providers WHERE provider_id = ?",
            (provider_id,),
        )
        caps = ProviderCapabilities(
            streaming=any(m.streaming for m in ALL_FREE_MODEL_ENTRIES if m.provider_id == provider_id),
            tool_support=any(
                m.tool_support for m in ALL_FREE_MODEL_ENTRIES if m.provider_id == provider_id
            ),
            structured_output=any(
                m.structured_output for m in ALL_FREE_MODEL_ENTRIES if m.provider_id == provider_id
            ),
            rate_limit_rpm=sample.rate_limit_rpm,
        )
        if existing is None:
            row_id = str(uuid4())
            await self._db.execute(
                """
                INSERT INTO providers(
                    id, schema_version, provider_id, display_name, kind,
                    free, free_status, base_url, auth_status, capabilities,
                    streaming, tool_support, structured_output, rate_limit_rpm,
                    metadata, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    row_id,
                    SCHEMA_VERSION,
                    provider_id,
                    _PROVIDER_DISPLAY.get(provider_id, provider_id),
                    kind.value,
                    1 if kind != ProviderKind.CUSTOM else 0,
                    FreeStatus.CONFIRMED.value,
                    None,
                    AuthStatus.MISSING.value,
                    caps.model_dump_json(),
                    1 if caps.streaming else 0,
                    1 if caps.tool_support else 0,
                    1 if caps.structured_output else 0,
                    caps.rate_limit_rpm,
                    "{}",
                    now,
                    now,
                ),
            )
        else:
            await self._db.execute(
                """
                UPDATE providers SET display_name = ?, kind = ?, streaming = ?,
                       tool_support = ?, structured_output = ?, rate_limit_rpm = ?,
                       capabilities = ?, updated_at = ?
                WHERE provider_id = ?
                """,
                (
                    _PROVIDER_DISPLAY.get(provider_id, provider_id),
                    kind.value,
                    1 if caps.streaming else 0,
                    1 if caps.tool_support else 0,
                    1 if caps.structured_output else 0,
                    caps.rate_limit_rpm,
                    caps.model_dump_json(),
                    now,
                    provider_id,
                ),
            )

    async def _upsert_model(self, entry: ModelCatalogEntry, now: str) -> None:
        provider = await self._db.fetchone(
            "SELECT id FROM providers WHERE provider_id = ?", (entry.provider_id,)
        )
        if provider is None:
            log.warning("catalog_skip_model_no_provider", provider_id=entry.provider_id, model=entry.model_key)
            return
        provider_pk = provider["id"]
        pricing = ModelPricing(
            input_per_mtok=entry.pricing_input_per_mtok,
            output_per_mtok=entry.pricing_output_per_mtok,
        )
        existing = await self._db.fetchone(
            "SELECT id FROM models WHERE provider_id = ? AND model_key = ?",
            (provider_pk, entry.model_key),
        )
        metadata = {
            "trust_level": entry.trust_level.value,
            "categories": [c.value for c in entry.categories],
            "notes": entry.notes,
            "last_verified": entry.last_verified.isoformat() if entry.last_verified else None,
            "expires_at": entry.expires_at.isoformat() if entry.expires_at else None,
        }
        free = 1 if (entry.free and entry.free_status == "confirmed") else 0
        free_status = (
            FreeStatus.CONFIRMED.value
            if entry.free_status == "confirmed"
            else (FreeStatus.PAID.value if entry.free_status == "paid" else FreeStatus.UNKNOWN.value)
        )
        if existing is None:
            await self._db.execute(
                """
                INSERT INTO models(
                    id, schema_version, provider_id, model_key, display_name,
                    free, free_status, context_limit, tool_support, structured_output,
                    streaming, pricing_input_per_mtok, pricing_output_per_mtok,
                    metadata, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    str(uuid4()),
                    SCHEMA_VERSION,
                    provider_pk,
                    entry.model_key,
                    entry.display_name,
                    free,
                    free_status,
                    entry.context_limit,
                    1 if entry.tool_support else 0,
                    1 if entry.structured_output else 0,
                    1 if entry.streaming else 0,
                    pricing.input_per_mtok,
                    pricing.output_per_mtok,
                    _json(metadata),
                    now,
                    now,
                ),
            )
        else:
            await self._db.execute(
                """
                UPDATE models SET display_name = ?, free = ?, free_status = ?,
                       context_limit = ?, tool_support = ?, structured_output = ?,
                       streaming = ?, pricing_input_per_mtok = ?, pricing_output_per_mtok = ?,
                       metadata = ?, updated_at = ?
                WHERE id = ?
                """,
                (
                    entry.display_name,
                    free,
                    free_status,
                    entry.context_limit,
                    1 if entry.tool_support else 0,
                    1 if entry.structured_output else 0,
                    1 if entry.streaming else 0,
                    pricing.input_per_mtok,
                    pricing.output_per_mtok,
                    _json(metadata),
                    now,
                    existing["id"],
                ),
            )


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


def _json(d: dict) -> str:
    import json

    return json.dumps(d, sort_keys=True)
