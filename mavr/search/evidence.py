"""Evidence-item persistence helpers.

An :class:`mavr.schemas.entities.EvidenceItem` is the durable handle
that findings, PoCs, and final reports reference INSTEAD of raw
URLs. If the page disappears, the UUID + the stored artifacts
still exist, and an auditor can re-derive what the agent saw.

This module provides:

* :func:`record_evidence` — write the row to ``evidence_items``;
* :func:`get_evidence` — fetch by UUID;
* :func:`list_evidence_for_campaign` — list everything for a campaign;
* :func:`record_extracted_source` — write the matching
  ``extracted_sources`` row (the extraction journal);
* :func:`link_evidence_to_finding` — append the evidence UUID to a
  finding version's ``evidence_refs`` JSON list.

The DB parameter is always an :class:`aiosqlite.Connection`. The
helpers do not commit; the caller owns the transaction.
"""
from __future__ import annotations

import json
from collections.abc import Iterable
from typing import Any

from mavr.agents import identity as identity_mod
from mavr.observability.logging import get_logger
from mavr.schemas import entities as schema

log = get_logger(__name__)


async def record_evidence(
    conn: Any,
    *,
    evidence: schema.EvidenceItem,
) -> None:
    """Persist an :class:`EvidenceItem` row."""
    await conn.execute(
        "INSERT INTO evidence_items("
        "id, schema_version, campaign_id, source_url, retrieved_at, "
        "content_hash, byte_length, content_type, raw_artifact_id, "
        "extracted_artifact_id, notes, created_at"
        ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            evidence.id,
            evidence.schema_version,
            evidence.campaign_id,
            evidence.source_url,
            evidence.retrieved_at.isoformat(),
            evidence.content_hash,
            evidence.byte_length,
            evidence.content_type,
            evidence.raw_artifact_id,
            evidence.extracted_artifact_id,
            evidence.notes,
            evidence.created_at.isoformat(),
        ),
    )
    log.info(
        "evidence_recorded",
        evidence_id=evidence.id,
        campaign_id=evidence.campaign_id,
        source_url=evidence.source_url,
    )


async def get_evidence(conn: Any, evidence_id: str) -> schema.EvidenceItem | None:
    """Load a single :class:`EvidenceItem` by UUID. Returns ``None`` if missing."""
    cur = await conn.execute(
        "SELECT * FROM evidence_items WHERE id = ?", (evidence_id,)
    )
    row = await cur.fetchone()
    if row is None:
        return None
    return _row_to_evidence(row)


async def list_evidence_for_campaign(
    conn: Any, campaign_id: str
) -> list[schema.EvidenceItem]:
    """List every :class:`EvidenceItem` for a campaign, newest first."""
    cur = await conn.execute(
        "SELECT * FROM evidence_items WHERE campaign_id = ? "
        "ORDER BY created_at DESC",
        (campaign_id,),
    )
    rows = await cur.fetchall()
    return [_row_to_evidence(r) for r in rows]


async def record_extracted_source(
    conn: Any, *, source: schema.ExtractedSource
) -> None:
    """Persist the extraction-journal row."""
    await conn.execute(
        "INSERT INTO extracted_sources("
        "id, schema_version, task_id, campaign_id, source_url, final_url, "
        "content_type, byte_length, content_hash, raw_artifact_id, "
        "extracted_artifact_id, http_status, redirect_count, fetched_at, "
        "extractor, metadata"
        ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            source.id,
            source.schema_version,
            source.task_id,
            source.campaign_id,
            source.source_url,
            source.final_url,
            source.content_type,
            source.byte_length,
            source.content_hash,
            source.raw_artifact_id,
            source.extracted_artifact_id,
            source.http_status,
            source.redirect_count,
            source.fetched_at.isoformat(),
            source.extractor,
            json.dumps(source.metadata, ensure_ascii=False),
        ),
    )


async def link_evidence_to_finding(
    conn: Any,
    *,
    finding_id: str,
    version: int,
    evidence_ids: Iterable[str],
) -> None:
    """Append ``evidence_ids`` to ``finding_versions.evidence_refs``.

    Idempotent: evidence UUIDs already in the list are not duplicated.
    """
    cur = await conn.execute(
        "SELECT evidence_refs FROM finding_versions WHERE finding_id = ? "
        "AND version = ?",
        (finding_id, version),
    )
    row = await cur.fetchone()
    if row is None:
        log.warning(
            "link_evidence_no_version",
            finding_id=finding_id,
            version=version,
        )
        return
    try:
        existing = json.loads(row["evidence_refs"]) if row["evidence_refs"] else []
    except json.JSONDecodeError:
        existing = []
    seen = set(existing)
    for evid in evidence_ids:
        if evid not in seen:
            existing.append(evid)
            seen.add(evid)
    await conn.execute(
        "UPDATE finding_versions SET evidence_refs = ? "
        "WHERE finding_id = ? AND version = ?",
        (json.dumps(existing, ensure_ascii=False), finding_id, version),
    )


def _row_to_evidence(row: Any) -> schema.EvidenceItem:
    from datetime import datetime

    return schema.EvidenceItem(
        id=row["id"],
        schema_version=row["schema_version"],
        campaign_id=row["campaign_id"],
        source_url=row["source_url"],
        retrieved_at=datetime.fromisoformat(row["retrieved_at"]),
        content_hash=row["content_hash"],
        byte_length=row["byte_length"],
        content_type=row["content_type"],
        raw_artifact_id=row["raw_artifact_id"],
        extracted_artifact_id=row["extracted_artifact_id"],
        notes=row["notes"] or "",
        created_at=datetime.fromisoformat(row["created_at"]),
    )


# ---- re-export ------------------------------------------------------------


__all__ = [
    "record_evidence",
    "get_evidence",
    "list_evidence_for_campaign",
    "record_extracted_source",
    "link_evidence_to_finding",
]


# Suppress unused-import warning when the helpers aren't called.
_ = (identity_mod,)
