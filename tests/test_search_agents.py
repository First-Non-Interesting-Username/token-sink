"""Tests for mavr.search.agents.

Covers the search and extraction subagent spawners + handlers. We
patch the network call so the tests stay offline.
"""
from __future__ import annotations

import json
import subprocess
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import pytest

from mavr.config.loader import SearchConfig
from mavr.orchestrator import queue, runtime
from mavr.schemas import entities as schema
from mavr.search import agents, engine
from mavr.storage.artifacts import ArtifactStore
from mavr.storage.database import Database, apply_migrations

# ---- helpers --------------------------------------------------------------


def _setup_db(tmp_path) -> Database:
    db = Database(str(tmp_path / "phase5-agents.db"))
    return db


async def _seed(db: Database) -> str:
    await apply_migrations(db, "up")
    cid = str(uuid4())
    now = datetime.now(UTC).isoformat()
    await db.execute(
        "INSERT INTO campaigns(id, schema_version, name, target_spec, state, "
        "created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            cid,
            schema.SCHEMA_VERSION,
            "agents",
            "{}",
            "active",
            now,
            now,
        ),
    )
    return cid


async def _insert_scope(
    db: Database, campaign_id: str, allowed_targets: list[str]
) -> None:
    sid = str(uuid4())
    now = datetime.now(UTC).isoformat()
    await db.execute(
        "INSERT INTO scope_policies("
        "id, schema_version, campaign_id, allowed_targets, allowed_methods, "
        "action_allowlist, rate_limit_per_minute, active_testing, "
        "explicit_unsafe_networking, human_approved, created_at, updated_at"
        ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            sid,
            schema.SCHEMA_VERSION,
            campaign_id,
            json.dumps(allowed_targets),
            json.dumps(["GET", "HEAD"]),
            json.dumps(["read"]),
            60,
            0,
            0,
            0,
            now,
            now,
        ),
    )


async def _make_parent(db: Database, campaign_id: str) -> schema.Agent:
    parent_id = str(uuid4())
    now = datetime.now(UTC)
    parent = schema.Agent(
        id=parent_id,
        schema_version=schema.SCHEMA_VERSION,
        role=schema.AgentRole.SUBAGENT,
        status=schema.AgentStatus.RUNNING,
        campaign_id=campaign_id,
        created_at=now,
        updated_at=now,
    )
    from mavr.orchestrator import agents as orch_agents

    async with db.acquire() as conn:
        await orch_agents.insert(conn, parent)
    return parent


def _make_curl_result(*, body: bytes, status: int = 200, content_type: str = "text/html; charset=utf-8") -> subprocess.CompletedProcess:
    head = f"HTTP/1.1 {status} OK\r\nContent-Type: {content_type}\r\nContent-Length: {len(body)}\r\n\r\n"
    return subprocess.CompletedProcess(args=["curl"], returncode=0, stdout=head.encode() + body, stderr=b"")


# ---- search_subagent spawner + handler -----------------------------------


class _StubDDGS:
    def __init__(self, rows: list[dict[str, Any]]) -> None:
        self._rows = rows
    def __enter__(self) -> Any: return self
    def __exit__(self, *a: Any) -> None: return None
    def text(self, *a: Any, **kw: Any) -> Any: return list(self._rows)


@pytest.mark.asyncio
async def test_search_subagent_full_path(tmp_path, monkeypatch) -> None:
    db = _setup_db(tmp_path)
    cid = await _seed(db)
    await _insert_scope(db, cid, ["allowed.example.com"])
    parent = await _make_parent(db, cid)

    rows = [
        {"href": "https://allowed.example.com/p", "title": "A", "body": "S"},
        {"href": "https://blocked.example.com/p", "title": "B", "body": "S"},
    ]
    import ddgs as ddgs_mod

    import mavr.search.engine as engine_mod

    monkeypatch.setattr(ddgs_mod, "DDGS", lambda: _StubDDGS(rows))
    monkeypatch.setattr(
        engine_mod.ScopePolicyEngine, "resolve_now",
        staticmethod(lambda host: ("1.2.3.4",) if "allowed" in host else ("5.6.7.8",)),
    )

    child, task = await agents.search_subagent(
        db, parent=parent, request=agents.SearchRequest(query="q")
    )
    assert child.role == schema.AgentRole.SEARCH
    assert child.parent_id == parent.id

    # Lease + execute
    async with db.acquire() as conn:
        leased = await queue.dequeue(
            conn, owner="worker", kinds=[schema.TaskKind.GENERIC]
        )
    assert leased and leased[0].id == task.id

    eng = engine.SearchEngine(config=SearchConfig(top_n=10))
    handler = agents.SearchAgentHandler(eng)

    async def factory():
        return await db.connect()

    final = await runtime.execute(
        factory, task=leased[0], agent=child, handler=handler
    )
    assert final.status == schema.TaskStatus.COMPLETED
    result = final.result
    assert result is not None
    assert result["query"] == "q"
    assert result["result_count"] == 2
    assert "https://allowed.example.com/p" in result["in_scope_urls"]
    assert "https://blocked.example.com/p" not in result["in_scope_urls"]

    # The search_results table was populated
    async with db.acquire() as conn:
        cur = await conn.execute(
            "SELECT COUNT(*) AS c FROM search_results WHERE campaign_id = ?",
            (cid,),
        )
        row = await cur.fetchone()
        assert int(row["c"]) == 2


# ---- extraction_subagent spawner + handler -------------------------------


@pytest.mark.asyncio
async def test_extraction_subagent_persists_evidence(
    tmp_path, monkeypatch
) -> None:
    db = _setup_db(tmp_path)
    cid = await _seed(db)
    await _insert_scope(db, cid, ["example.com"])
    parent = await _make_parent(db, cid)
    artifacts = ArtifactStore(tmp_path / "artifacts")

    body = b"<html><body><h1>Hi</h1><script>alert(1)</script></body></html>"
    cp = _make_curl_result(body=body)
    monkeypatch.setattr(
        "mavr.search.extract.subprocess.run", lambda *a, **kw: cp
    )

    child, task = await agents.extraction_subagent(
        db,
        parent=parent,
        request=agents.ExtractionRequest(url="https://example.com/page"),
    )
    assert child.role == schema.AgentRole.EXTRACTION

    async with db.acquire() as conn:
        leased = await queue.dequeue(
            conn, owner="worker", kinds=[schema.TaskKind.GENERIC]
        )
    assert leased and leased[0].id == task.id

    handler = agents.ExtractionAgentHandler(artifacts=artifacts)

    async def factory():
        return await db.connect()

    final = await runtime.execute(
        factory, task=leased[0], agent=child, handler=handler
    )
    assert final.status == schema.TaskStatus.COMPLETED
    result = final.result
    assert result is not None
    assert result["extractor"] == "curl"
    assert result["byte_length"] == len(body)
    eid = result["evidence_id"]
    # Evidence row exists in DB.
    async with db.acquire() as conn:
        cur = await conn.execute(
            "SELECT * FROM evidence_items WHERE id = ?", (eid,)
        )
        row = await cur.fetchone()
        assert row is not None
        assert row["source_url"] == "https://example.com/page"
        # Raw artifact is recoverable
        assert artifacts.read(row["raw_artifact_id"]) == body
    # Network budget was charged
    async with db.acquire() as conn:
        cur = await conn.execute(
            "SELECT network_requests_used FROM agents WHERE id = ?", (child.id,)
        )
        row = await cur.fetchone()
        assert int(row["network_requests_used"]) == 1


@pytest.mark.asyncio
async def test_extraction_subagent_blocks_ssrf(tmp_path, monkeypatch) -> None:
    db = _setup_db(tmp_path)
    cid = await _seed(db)
    await _insert_scope(db, cid, [])
    parent = await _make_parent(db, cid)
    artifacts = ArtifactStore(tmp_path / "artifacts")

    body = b"x"
    cp = _make_curl_result(body=body)
    monkeypatch.setattr(
        "mavr.search.extract.subprocess.run", lambda *a, **kw: cp
    )

    child, task = await agents.extraction_subagent(
        db,
        parent=parent,
        request=agents.ExtractionRequest(url="http://127.0.0.1/secret"),
    )

    async with db.acquire() as conn:
        leased = await queue.dequeue(
            conn, owner="worker", kinds=[schema.TaskKind.GENERIC]
        )

    handler = agents.ExtractionAgentHandler(artifacts=artifacts)

    async def factory():
        return await db.connect()

    final = await runtime.execute(
        factory, task=leased[0], agent=child, handler=handler
    )
    # Task is quarantined with a policy-classification error.
    assert final.status == schema.TaskStatus.QUARANTINED
    assert "policy" in (final.error or "")


@pytest.mark.asyncio
async def test_extraction_subagent_metadata_blocked(tmp_path, monkeypatch) -> None:
    db = _setup_db(tmp_path)
    cid = await _seed(db)
    await _insert_scope(db, cid, [])
    parent = await _make_parent(db, cid)
    artifacts = ArtifactStore(tmp_path / "artifacts")
    monkeypatch.setattr(
        "mavr.search.extract.subprocess.run", lambda *a, **kw: _make_curl_result(body=b"{}")
    )

    child, task = await agents.extraction_subagent(
        db,
        parent=parent,
        request=agents.ExtractionRequest(
            url="http://169.254.169.254/latest/meta-data"
        ),
    )
    async with db.acquire() as conn:
        leased = await queue.dequeue(conn, owner="worker")

    handler = agents.ExtractionAgentHandler(artifacts=artifacts)

    async def factory():
        return await db.connect()

    final = await runtime.execute(
        factory, task=leased[0], agent=child, handler=handler
    )
    assert final.status == schema.TaskStatus.QUARANTINED
    assert "policy" in (final.error or "")
