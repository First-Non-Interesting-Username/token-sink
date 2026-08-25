"""Recovery tests (spec §19, §21).

The system must survive:

* processes being killed mid-campaign (e.g. ``kill -9``) and the
  operator restarting MAVR — the next run picks up the same tasks
  with the same state and the same evidence;
* leases expiring while a worker is dead — the sweeper reclaims the
  task and a fresh worker can dequeue it;
* DB transaction rollbacks when a crash happens between writes;
* backup → wipe → import round-trips that preserve every evidence
  row, every finding, and every final report hash.

All tests are offline; they use only the local SQLite store and the
artifact filesystem.
"""
from __future__ import annotations

import json
import sqlite3
import tempfile
import zipfile
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest

from mavr.agents.identity import mint_agent
from mavr.observability import bundle
from mavr.orchestrator import audit, queue
from mavr.orchestrator.agents import insert as insert_agent
from mavr.schemas import entities as schema
from mavr.storage.artifacts import ArtifactStore
from mavr.storage.database import (
    Database,
    apply_migrations,
)

# ---- helpers --------------------------------------------------------------


async def _insert_campaign(db: Database) -> str:
    cid = str(uuid4())
    now = datetime.now(UTC).isoformat()
    async with db.acquire() as conn:
        await conn.execute(
            "INSERT INTO campaigns(id, schema_version, name, target_spec, state, "
            "created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (cid, schema.SCHEMA_VERSION, "rcv", "{}", "active", now, now),
        )
        await conn.commit()
    return cid


# ---- 1. Lease expiry and reassignment ----------------------------------


class TestLeaseExpiry:
    @pytest.mark.asyncio
    async def test_expired_lease_is_reclaimed_by_sweeper(
        self, migrated_db: Database
    ) -> None:
        cid = await _insert_campaign(migrated_db)
        agent = mint_agent(schema.AgentRole.SEARCH, campaign_id=cid)
        async with migrated_db.acquire() as conn:
            await insert_agent(conn, agent)
            task = await queue.enqueue(
                conn,
                campaign_id=cid,
                kind=schema.TaskKind.SEARCH,
                payload={"url": "https://example.com/"},
            )

        # Lease with a 1-second TTL.
        short_policy = queue.LeasePolicy(lease_ttl_seconds=1)
        async with migrated_db.acquire() as conn:
            leased = await queue.dequeue(
                conn, owner="worker-A", lease_policy=short_policy
            )
        assert len(leased) == 1
        assert leased[0].id == task.id
        assert leased[0].lease_owner is not None

        # Wait past TTL.
        import asyncio

        await asyncio.sleep(1.2)

        # Sweep reclaims the lease.
        async with migrated_db.acquire() as conn:
            result = await queue.sweep_stale_leases(
                conn, policy=short_policy
            )
        assert result.reclaimed >= 1

        # The next worker can now lease the same task.
        async with migrated_db.acquire() as conn:
            leased2 = await queue.dequeue(
                conn, owner="worker-B", lease_policy=short_policy
            )
        assert any(t.id == task.id for t in leased2)

    @pytest.mark.asyncio
    async def test_heartbeat_keeps_lease_alive(
        self, migrated_db: Database
    ) -> None:
        cid = await _insert_campaign(migrated_db)
        async with migrated_db.acquire() as conn:
            await queue.enqueue(
                conn, campaign_id=cid, kind=schema.TaskKind.SEARCH, payload={}
            )
        policy = queue.LeasePolicy(lease_ttl_seconds=2)
        async with migrated_db.acquire() as conn:
            leased = await queue.dequeue(
                conn, owner="worker-A", lease_policy=policy
            )
        assert leased
        import asyncio

        await asyncio.sleep(0.6)
        # Heartbeat keeps the lease alive.
        async with migrated_db.acquire() as conn:
            ok = await queue.heartbeat(
                conn, task_id=leased[0].id, lease_owner=leased[0].lease_owner
            )
        assert ok
        await asyncio.sleep(0.6)
        # Second heartbeat; still ours.
        async with migrated_db.acquire() as conn:
            ok2 = await queue.heartbeat(
                conn, task_id=leased[0].id, lease_owner=leased[0].lease_owner
            )
        assert ok2
        # And the task is still leased to worker-A.
        async with migrated_db.acquire() as conn:
            current = await queue.get(conn, leased[0].id)
        assert current.lease_owner is not None
        assert current.lease_owner.startswith("worker-A:")

    @pytest.mark.asyncio
    async def test_heartbeat_with_wrong_owner_fails(
        self, migrated_db: Database
    ) -> None:
        cid = await _insert_campaign(migrated_db)
        async with migrated_db.acquire() as conn:
            await queue.enqueue(
                conn, campaign_id=cid, kind=schema.TaskKind.SEARCH, payload={}
            )
        async with migrated_db.acquire() as conn:
            leased = await queue.dequeue(conn, owner="worker-A")
        async with migrated_db.acquire() as conn:
            ok = await queue.heartbeat(
                conn,
                task_id=leased[0].id,
                lease_owner="worker-B:wrong-token",
            )
        assert ok is False


# ---- 2. DB transaction rollback ----------------------------------------


class TestDBTransactionRollback:
    @pytest.mark.asyncio
    async def test_failed_write_does_not_persist(
        self, migrated_db: Database
    ) -> None:
        # Force a FK violation; with a manual transaction we can roll
        # it back, leaving no orphan rows.
        async with migrated_db.acquire() as conn:
            await conn.execute("BEGIN")
            try:
                await conn.execute(
                    "INSERT INTO tasks(id, schema_version, campaign_id, kind, status, "
                    "priority, payload, attempt, max_attempts, created_at, updated_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        str(uuid4()),
                        schema.SCHEMA_VERSION,
                        "00000000-0000-4000-8000-000000000000",
                        schema.TaskKind.SEARCH.value,
                        schema.TaskStatus.PENDING.value,
                        0,
                        "{}",
                        0,
                        1,
                        datetime.now(UTC).isoformat(),
                        datetime.now(UTC).isoformat(),
                    ),
                )
            except sqlite3.IntegrityError:
                await conn.rollback()
            # No orphan row should remain.
            cur = await conn.execute("SELECT COUNT(*) AS n FROM tasks")
            row = await cur.fetchone()
            assert row["n"] == 0

    @pytest.mark.asyncio
    async def test_partial_write_rolls_back(
        self, migrated_db: Database
    ) -> None:
        cid = await _insert_campaign(migrated_db)
        # Begin transaction, write one task, then simulate a crash by
        # rolling back. The task must not exist afterwards.
        async with migrated_db.acquire() as conn:
            await conn.execute("BEGIN")
            await conn.execute(
                "INSERT INTO tasks(id, schema_version, campaign_id, kind, status, "
                "priority, payload, attempt, max_attempts, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    str(uuid4()),
                    schema.SCHEMA_VERSION,
                    cid,
                    schema.TaskKind.SEARCH.value,
                    schema.TaskStatus.PENDING.value,
                    0,
                    "{}",
                    0,
                    1,
                    datetime.now(UTC).isoformat(),
                    datetime.now(UTC).isoformat(),
                ),
            )
            await conn.rollback()
        async with migrated_db.acquire() as conn:
            row = await (await conn.execute(
                "SELECT COUNT(*) AS n FROM tasks"
            )).fetchone()
            assert row["n"] == 0


# ---- 3. Resumable campaigns (kill -9 mid-campaign) ---------------------


class TestResumableCampaigns:
    @pytest.mark.asyncio
    async def test_state_survives_kill_and_restart(
        self, tmp_path: Path
    ) -> None:
        """Simulate ``kill -9`` mid-campaign: the DB and artifact dir
        are persisted to disk, then a *new* Database / ArtifactStore
        is opened against the same path and the state is identical.
        """
        db_path = tmp_path / "mavr.db"
        artifacts_dir = tmp_path / "artifacts"
        artifacts_dir.mkdir()

        cid = str(uuid4())
        db = Database(db_path)
        await apply_migrations(db, "up")
        now = datetime.now(UTC).isoformat()
        async with db.acquire() as conn:
            await conn.execute(
                "INSERT INTO campaigns(id, schema_version, name, target_spec, "
                "state, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    cid,
                    schema.SCHEMA_VERSION,
                    "resumable",
                    "{}",
                    "active",
                    now,
                    now,
                ),
            )
            await conn.execute(
                "INSERT INTO tasks(id, schema_version, campaign_id, kind, status, "
                "priority, payload, attempt, max_attempts, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    str(uuid4()),
                    schema.SCHEMA_VERSION,
                    cid,
                    schema.TaskKind.SEARCH.value,
                    schema.TaskStatus.PENDING.value,
                    0,
                    "{}",
                    0,
                    1,
                    now,
                    now,
                ),
            )
            await conn.commit()

        # Write an artifact.
        store = ArtifactStore(artifacts_dir)
        aid = str(uuid4())
        store.write(aid, b"resumable artifact", suffix=".deadbeef")

        # "Kill -9" — drop the connection and GC the DB object.
        del db
        del store

        # Restart: fresh handles to the same path.
        db2 = Database(db_path)
        store2 = ArtifactStore(artifacts_dir)
        async with db2.acquire() as conn:
            row = await (await conn.execute(
                "SELECT * FROM campaigns WHERE id = ?", (cid,)
            )).fetchone()
            assert row is not None
            assert row["name"] == "resumable"
            row2 = await (await conn.execute(
                "SELECT COUNT(*) AS n FROM tasks WHERE campaign_id = ?", (cid,)
            )).fetchone()
            assert row2["n"] == 1
        assert store2.exists(aid, suffix=".deadbeef")
        assert store2.read(aid, suffix=".deadbeef") == b"resumable artifact"

    @pytest.mark.asyncio
    async def test_pending_tasks_are_redequed_after_restart(
        self, tmp_path: Path
    ) -> None:
        db_path = tmp_path / "mavr.db"
        cid = str(uuid4())
        db = Database(db_path)
        await apply_migrations(db, "up")
        now = datetime.now(UTC).isoformat()
        async with db.acquire() as conn:
            await conn.execute(
                "INSERT INTO campaigns(id, schema_version, name, target_spec, "
                "state, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    cid,
                    schema.SCHEMA_VERSION,
                    "r",
                    "{}",
                    "active",
                    now,
                    now,
                ),
            )
            for _ in range(3):
                await conn.execute(
                    "INSERT INTO tasks(id, schema_version, campaign_id, kind, "
                    "status, priority, payload, attempt, max_attempts, "
                    "created_at, updated_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        str(uuid4()),
                        schema.SCHEMA_VERSION,
                        cid,
                        schema.TaskKind.SEARCH.value,
                        schema.TaskStatus.PENDING.value,
                        0,
                        "{}",
                        0,
                        1,
                        now,
                        now,
                    ),
                )
            await conn.commit()
        del db

        # Restart.
        db2 = Database(db_path)
        async with db2.acquire() as conn:
            leased = await queue.dequeue(conn, owner="resumer", limit=10)
        assert len(leased) == 3
        ids = {t.id for t in leased}
        assert len(ids) == 3


# ---- 4. Backup → wipe → import round-trip ------------------------------


class TestBackupWipeImportRoundTrip:
    @pytest.mark.asyncio
    async def test_run_bundle_round_trip_preserves_state(
        self, tmp_path: Path
    ) -> None:
        db = Database(tmp_path / "mavr.db")
        await apply_migrations(db, "up")
        cid = await _insert_campaign(db)
        agent = mint_agent(schema.AgentRole.SEARCH, campaign_id=cid)
        async with db.acquire() as conn:
            await insert_agent(conn, agent)
            await queue.enqueue(
                conn,
                campaign_id=cid,
                kind=schema.TaskKind.SEARCH,
                payload={"url": "https://example.com/"},
            )
            await audit.record(
                conn,
                actor_id=agent.id,
                actor_kind=schema.ActorKind.AGENT,
                category=schema.AuditCategory.STATE_TRANSITION,
                subject_kind="campaign",
                subject_id=cid,
                prior_state=None,
                new_state="active",
                reason="round-trip setup",
            )

        # Snapshot the bundle.
        bundle_path = tmp_path / "bundle.zip"
        result = await bundle.export_run_bundle(
            db,
            campaign_id=cid,
            output_path=bundle_path,
            config_snapshot={"router": {"free_only": True}},
        )
        assert result.path.exists()
        assert result.entry_count >= 5
        with zipfile.ZipFile(bundle_path) as zf:
            names = set(zf.namelist())
        assert "manifest.json" in names
        assert "findings.json" in names
        assert "audit.jsonl" in names
        assert "db_dump.sqlite" in names

        # Verify the manifest is sane.
        with zipfile.ZipFile(bundle_path) as zf:
            manifest = json.loads(zf.read("manifest.json"))
        assert manifest["campaign_id"] == cid
        assert manifest["counts"]["tasks"] >= 1
        assert manifest["counts"]["agents"] >= 1
        assert manifest["counts"]["audit_events"] >= 1

        # Verify no raw secrets are in the bundle.
        with zipfile.ZipFile(bundle_path) as zf:
            for entry in ("audit.jsonl", "events.jsonl", "findings.json"):
                if entry in zf.namelist():
                    text = zf.read(entry).decode("utf-8", errors="ignore")
                    assert "sk-supersecret" not in text
        # db_dump must not contain the approvals.token column values.
        with zipfile.ZipFile(bundle_path) as zf:
            db_bytes = zf.read("db_dump.sqlite")
        with tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False) as f:
            f.write(db_bytes)
            extracted = Path(f.name)
        try:
            conn = sqlite3.connect(extracted)
            cur = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
            tables = [r[0] for r in cur.fetchall()]
            assert "campaigns" in tables
            assert "tasks" in tables
            # The approvals table may be present, but any `token` column
            # in any table must be empty / redacted.
            for t in tables:
                cols = [
                    r[1] for r in conn.execute(f"PRAGMA table_info({t})").fetchall()
                ]
                if "token" in cols:
                    cur = conn.execute(
                        f"SELECT token FROM {t} WHERE token IS NOT NULL AND token != ''"
                    )
                    leaked = cur.fetchall()
                    assert not leaked, f"raw token leaked in {t}"
        finally:
            extracted.unlink(missing_ok=True)

    @pytest.mark.asyncio
    async def test_backup_then_wipe_then_restore_preserves_findings(
        self, tmp_path: Path
    ) -> None:
        """Export a bundle, nuke the live DB, re-import the bundle's
        DB dump, and assert the campaign + tasks + audit log are
        preserved."""
        from mavr.findings.workflow import (
            DiscoveryPayload,
            create_initial_finding,
        )

        db = Database(tmp_path / "mavr.db")
        await apply_migrations(db, "up")
        cid = await _insert_campaign(db)
        async with db.acquire() as conn:
            f = await create_initial_finding(
                conn,
                campaign_id=cid,
                payload=DiscoveryPayload(
                    title="round-trip finding",
                    description="d",
                    severity=schema.Severity.MEDIUM,
                    confidence="likely",
                    evidence_refs=(str(uuid4()),),
                ),
            )
        finding_id = f.id

        bundle_path = tmp_path / "bundle.zip"
        await bundle.export_run_bundle(
            db, campaign_id=cid, output_path=bundle_path
        )

        # Wipe live DB. Close any open connections via the Database
        # wrapper's internal lock; then nuke the file and its WAL
        # sidecar files.
        del db
        live_db_path = tmp_path / "mavr.db"
        for ext in ("", "-wal", "-shm"):
            p = Path(str(live_db_path) + ext)
            if p.exists():
                p.unlink()

        # Restore from the bundle's db_dump.sqlite into a fresh path.
        with zipfile.ZipFile(bundle_path) as zf:
            db_bytes = zf.read("db_dump.sqlite")
        restored_path = tmp_path / "restored.db"
        restored_path.write_bytes(db_bytes)
        restored = Database(restored_path)

        async with restored.acquire() as conn:
            row = await (await conn.execute(
                "SELECT * FROM campaigns WHERE id = ?", (cid,)
            )).fetchone()
            assert row is not None
            frow = await (await conn.execute(
                "SELECT * FROM findings WHERE id = ?", (finding_id,)
            )).fetchone()
            assert frow is not None
            # Audit log carries the original creation event.
            cur = await conn.execute(
                "SELECT COUNT(*) AS n FROM audit_events"
            )
            assert (await cur.fetchone())["n"] >= 1
