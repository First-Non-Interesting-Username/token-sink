"""Tests for mavr.search.evidence.

Round-trips EvidenceItem + ExtractedSource rows through the DB and
verifies that the link_evidence_to_finding helper is idempotent.
"""
from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from uuid import uuid4

from mavr.schemas import entities as schema
from mavr.search import evidence
from mavr.storage.database import Database, apply_migrations


def _make_db(tmp_path) -> Database:
    db = Database(str(tmp_path / "phase5-ev.db"))
    asyncio.run(apply_migrations(db, "up"))
    return db


def _seed_campaign(db: Database) -> str:
    cid = str(uuid4())
    now = datetime.now(UTC).isoformat()
    asyncio.run(db.execute(
        "INSERT INTO campaigns(id, schema_version, name, target_spec, state, "
        "created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            cid,
            schema.SCHEMA_VERSION,
            "ev",
            "{}",
            "active",
            now,
            now,
        ),
    ))
    return cid


def test_record_and_get_evidence(tmp_path) -> None:
    db = _make_db(tmp_path)
    cid = _seed_campaign(db)
    now = datetime.now(UTC)
    raw_id = str(uuid4())
    extracted_id = str(uuid4())
    eid = str(uuid4())
    item = schema.EvidenceItem(
        id=eid,
        campaign_id=cid,
        source_url="https://example.com/x",
        retrieved_at=now,
        content_hash="a" * 64,
        byte_length=42,
        content_type="text/html",
        raw_artifact_id=raw_id,
        extracted_artifact_id=extracted_id,
        notes="",
    )

    async def go() -> schema.EvidenceItem | None:
        async with db.acquire() as conn:
            await evidence.record_evidence(conn, evidence=item)
            return await evidence.get_evidence(conn, eid)

    loaded = asyncio.run(go())
    assert loaded is not None
    assert loaded.id == eid
    assert loaded.content_hash == "a" * 64
    assert loaded.byte_length == 42
    assert loaded.source_url == "https://example.com/x"


def test_list_evidence_for_campaign(tmp_path) -> None:
    db = _make_db(tmp_path)
    cid = _seed_campaign(db)
    now = datetime.now(UTC)
    items = [
        schema.EvidenceItem(
            id=str(uuid4()),
            campaign_id=cid,
            source_url=f"https://example.com/{i}",
            retrieved_at=now,
            content_hash="b" * 64,
            byte_length=10,
            content_type="text/html",
            raw_artifact_id=str(uuid4()),
        )
        for i in range(3)
    ]

    async def go() -> list[schema.EvidenceItem]:
        async with db.acquire() as conn:
            for it in items:
                await evidence.record_evidence(conn, evidence=it)
            return await evidence.list_evidence_for_campaign(conn, cid)

    out = asyncio.run(go())
    assert len(out) == 3
    # newest first
    assert out[0].created_at >= out[1].created_at


def test_record_extracted_source(tmp_path) -> None:
    db = _make_db(tmp_path)
    cid = _seed_campaign(db)
    raw_id = str(uuid4())
    extracted_id = str(uuid4())
    src = schema.ExtractedSource(
        id=str(uuid4()),
        campaign_id=cid,
        source_url="https://example.com/p",
        final_url="https://example.com/p",
        content_type="text/html",
        byte_length=120,
        content_hash="c" * 64,
        raw_artifact_id=raw_id,
        extracted_artifact_id=extracted_id,
        http_status=200,
        redirect_count=0,
        extractor="curl",
        metadata={"foo": "bar"},
    )

    async def go() -> dict:
        async with db.acquire() as conn:
            await evidence.record_extracted_source(conn, source=src)
            cur = await conn.execute(
                "SELECT * FROM extracted_sources WHERE id = ?", (src.id,)
            )
            return dict(await cur.fetchone())

    row = asyncio.run(go())
    assert row["source_url"] == "https://example.com/p"
    assert row["extractor"] == "curl"
    assert row["http_status"] == 200
    # Metadata was JSON-serialized
    parsed = json.loads(row["metadata"])
    assert parsed == {"foo": "bar"}


def test_link_evidence_to_finding_idempotent(tmp_path) -> None:
    db = _make_db(tmp_path)
    cid = _seed_campaign(db)
    finding_id = str(uuid4())
    now = datetime.now(UTC).isoformat()
    asyncio.run(db.execute(
        "INSERT INTO findings(id, schema_version, campaign_id, title, state, "
        "current_version, tombstoned, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            finding_id,
            schema.SCHEMA_VERSION,
            cid,
            "test",
            "initial_findings",
            1,
            0,
            now,
            now,
        ),
    ))
    asyncio.run(db.execute(
        "INSERT INTO finding_versions(id, schema_version, finding_id, "
        "version, state, summary, body_markdown, evidence_refs, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            str(uuid4()),
            schema.SCHEMA_VERSION,
            finding_id,
            1,
            "initial_findings",
            "s",
            "b",
            "[]",
            now,
        ),
    ))

    e1 = str(uuid4())
    e2 = str(uuid4())

    async def go() -> list:
        async with db.acquire() as conn:
            await evidence.link_evidence_to_finding(
                conn, finding_id=finding_id, version=1, evidence_ids=[e1]
            )
            # Linking the same evidence id again must be a no-op.
            await evidence.link_evidence_to_finding(
                conn, finding_id=finding_id, version=1, evidence_ids=[e1]
            )
            # Linking a new one extends the list.
            await evidence.link_evidence_to_finding(
                conn, finding_id=finding_id, version=1, evidence_ids=[e2, e1]
            )
            cur = await conn.execute(
                "SELECT evidence_refs FROM finding_versions "
                "WHERE finding_id = ? AND version = ?",
                (finding_id, 1),
            )
            row = await cur.fetchone()
            return json.loads(row["evidence_refs"])

    refs = asyncio.run(go())
    assert refs == [e1, e2]


def test_link_evidence_missing_version_is_noop(tmp_path) -> None:
    db = _make_db(tmp_path)
    _seed_campaign(db)
    finding_id = str(uuid4())

    async def go() -> None:
        async with db.acquire() as conn:
            # No row exists for version 99; helper should warn but not raise.
            await evidence.link_evidence_to_finding(
                conn, finding_id=finding_id, version=99, evidence_ids=[str(uuid4())]
            )

    asyncio.run(go())        # did not raise
