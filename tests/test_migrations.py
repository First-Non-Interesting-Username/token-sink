"""Migration up/down tests for the initial schema."""
from __future__ import annotations

import sqlite3

import pytest

from mavr.storage.database import Database, apply_migrations


@pytest.mark.asyncio
async def test_apply_initial(db: Database) -> None:
    touched = await apply_migrations(db, "up")
    assert touched == [1, 2, 3, 4, 5, 6]
    async with db.acquire() as conn:
        cur = await conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
        )
        rows = [r["name"] for r in await cur.fetchall()]
    expected = {
        "agents",
        "approvals",
        "audit_events",
        "benchmark_results",
        "benchmark_runs",
        "campaigns",
        "circuit_breakers",
        "dead_letter",
        "evidence_items",
        "extracted_sources",
        "final_reports",
        "finding_leases",
        "finding_review_summaries",
        "finding_transitions",
        "finding_versions",
        "findings",
        "kill_switch",
        "metric_points",
        "model_scores",
        "models",
        "pocs",
        "providers",
        "quarantine_log",
        "reviews",
        "router_decisions",
        "scope_policies",
        "schema_migrations",
        "search_results",
        "submission_manifests",
        "system_events",
        "task_attempts",
        "task_dependencies",
        "tasks",
        "usage_events",
    }
    for tbl in expected:
        assert tbl in rows, f"missing table: {tbl}"


@pytest.mark.asyncio
async def test_apply_is_idempotent(db: Database) -> None:
    await apply_migrations(db, "up")
    touched = await apply_migrations(db, "up")
    assert touched == []


@pytest.mark.asyncio
async def test_uuid_check_constraint_enforced(db: Database) -> None:
    await apply_migrations(db, "up")
    async with db.acquire() as conn:
        with pytest.raises(sqlite3.IntegrityError):
            await conn.execute(
                "INSERT INTO campaigns (id, schema_version, name, target_spec, state, "
                "created_at, updated_at) VALUES (?,?,?,?,?,?,?)",
                (
                    "not-a-uuid",
                    "1.0.0",
                    "x",
                    "{}",
                    "draft",
                    "2026-01-01T00:00:00Z",
                    "2026-01-01T00:00:00Z",
                ),
            )


@pytest.mark.asyncio
async def test_event_id_unique(db: Database) -> None:
    await apply_migrations(db, "up")
    async with db.acquire() as conn:
        await conn.execute(
            "INSERT INTO audit_events (id, schema_version, event_id, actor_kind, category, created_at) "
            "VALUES (?,?,?,?,?,?)",
            (
                "11111111-1111-4111-8111-111111111111",
                "1.0.0",
                "evt-1",
                "system",
                "config",
                "2026-01-01T00:00:00Z",
            ),
        )
        with pytest.raises(sqlite3.IntegrityError):
            await conn.execute(
                "INSERT INTO audit_events (id, schema_version, event_id, actor_kind, category, created_at) "
                "VALUES (?,?,?,?,?,?)",
                (
                    "22222222-2222-4222-8222-222222222222",
                    "1.0.0",
                    "evt-1",
                    "system",
                    "config",
                    "2026-01-01T00:00:00Z",
                ),
            )


@pytest.mark.asyncio
async def test_finding_version_unique(db: Database) -> None:
    await apply_migrations(db, "up")
    async with db.acquire() as conn:
        # Need a campaign first (FK)
        await conn.execute(
            "INSERT INTO campaigns (id, schema_version, name, target_spec, state, "
            "created_at, updated_at) VALUES (?,?,?,?,?,?,?)",
            (
                "11111111-1111-4111-8111-111111111111",
                "1.0.0",
                "x",
                "{}",
                "draft",
                "2026-01-01T00:00:00Z",
                "2026-01-01T00:00:00Z",
            ),
        )
        await conn.execute(
            "INSERT INTO findings (id, schema_version, campaign_id, title, state, "
            "created_at, updated_at) VALUES (?,?,?,?,?,?,?)",
            (
                "22222222-2222-4222-8222-222222222222",
                "1.0.0",
                "11111111-1111-4111-8111-111111111111",
                "x",
                "initial_findings",
                "2026-01-01T00:00:00Z",
                "2026-01-01T00:00:00Z",
            ),
        )
        await conn.execute(
            "INSERT INTO finding_versions (id, schema_version, finding_id, version, "
            "state, summary, body_markdown, created_at) VALUES (?,?,?,?,?,?,?,?)",
            (
                "33333333-3333-4333-8333-333333333333",
                "1.0.0",
                "22222222-2222-4222-8222-222222222222",
                1,
                "initial_findings",
                "s",
                "b",
                "2026-01-01T00:00:00Z",
            ),
        )
        with pytest.raises(sqlite3.IntegrityError):
            await conn.execute(
                "INSERT INTO finding_versions (id, schema_version, finding_id, version, "
                "state, summary, body_markdown, created_at) VALUES (?,?,?,?,?,?,?,?)",
                (
                    "44444444-4444-4444-8444-444444444444",
                    "1.0.0",
                    "22222222-2222-4222-8222-222222222222",
                    1,
                    "initial_findings",
                    "s",
                    "b",
                    "2026-01-01T00:00:00Z",
                ),
            )


@pytest.mark.asyncio
async def test_revert_then_reapply(db: Database) -> None:
    await apply_migrations(db, "up")
    touched = await apply_migrations(db, "down")
    assert touched == [6, 5, 4, 3, 2, 1]
    async with db.acquire() as conn:
        cur = await conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='campaigns'"
        )
        assert (await cur.fetchone()) is None
    touched = await apply_migrations(db, "up")
    assert touched == [1, 2, 3, 4, 5, 6]
    async with db.acquire() as conn:
        cur = await conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='campaigns'"
        )
        assert (await cur.fetchone()) is not None
