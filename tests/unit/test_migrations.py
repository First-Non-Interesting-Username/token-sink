"""Tests for the forward-only migration runner (issue #130, PLAN §12)."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from storage.migrations import MigrationError, MigrationRunner, load_migrations
from storage.sqlite import SQLiteStorage


@pytest.fixture()
def migdir(tmp_path: Path) -> Path:
    d = tmp_path / "migrations"
    d.mkdir()
    return d


def _write(d: Path, version: int, name: str, sql: str) -> None:
    (d / f"{version:03d}_{name}.sql").write_text(sql)


def test_load_rejects_unexpected_files(migdir: Path):
    (migdir / "README.md").write_text("nope")
    with pytest.raises(MigrationError, match="unexpected file"):
        load_migrations(migdir)


def test_load_rejects_version_gaps(migdir: Path):
    _write(migdir, 1, "a", "CREATE TABLE a(x);")
    _write(migdir, 3, "c", "CREATE TABLE c(x);")
    with pytest.raises(MigrationError, match="gap"):
        load_migrations(migdir)


def test_apply_pending_and_noop_rerun(migdir: Path):
    _write(migdir, 1, "base", "CREATE TABLE t1(id TEXT PRIMARY KEY);")
    _write(migdir, 2, "extra", "ALTER TABLE t1 ADD COLUMN note TEXT DEFAULT '';")
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    runner = MigrationRunner(conn, migdir)

    assert runner.current_version() == 0
    assert [m.version for m in runner.pending()] == [1, 2]
    assert runner.migrate() == 2
    # Data written after v1 survives; v2 column usable.
    conn.execute("INSERT INTO t1 (id, note) VALUES ('a', 'kept')")
    # Re-running the fully-applied set is a no-op.
    assert runner.pending() == []
    assert runner.migrate() == 2


def test_edited_applied_migration_detected(migdir: Path):
    _write(migdir, 1, "base", "CREATE TABLE t1(id TEXT PRIMARY KEY);")
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    runner = MigrationRunner(conn, migdir)
    runner.migrate()

    # Retroactively edit the applied migration — history check must fail.
    _write(migdir, 1, "base", "CREATE TABLE t1(id TEXT PRIMARY KEY, evil TEXT);")
    with pytest.raises(MigrationError, match="hash mismatch"):
        runner.verify_history()


def test_downgrade_protection(migdir: Path):
    _write(migdir, 1, "base", "CREATE TABLE t1(id TEXT PRIMARY KEY);")
    _write(migdir, 2, "next", "CREATE TABLE t2(id TEXT PRIMARY KEY);")
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    MigrationRunner(conn, migdir).migrate()  # DB now at v2

    # Code that only knows v1 must refuse to operate on the newer DB.
    old_code_dir = migdir.parent / "old_migrations"
    old_code_dir.mkdir()
    _write(old_code_dir, 1, "base", "CREATE TABLE t1(id TEXT PRIMARY KEY);")
    stale_runner = MigrationRunner(conn, old_code_dir)
    with pytest.raises(MigrationError, match="downgrade"):
        stale_runner.verify_history()


def test_failed_migration_rolls_back_completely(migdir: Path):
    _write(migdir, 1, "good", "CREATE TABLE t1(id TEXT PRIMARY KEY);")
    _write(migdir, 2, "bad", "CREATE TABLE t2(id TEXT PRIMARY KEY);\nTHIS IS NOT SQL;")
    _write(migdir, 3, "never", "CREATE TABLE t3(id TEXT PRIMARY KEY);")
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    runner = MigrationRunner(conn, migdir)
    with pytest.raises(MigrationError, match="migration 002"):
        runner.migrate()
    # History stops at v1; partial v2 DDL is rolled back; v3 never ran.
    assert runner.current_version() == 1
    tables = {r["name"] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert "t1" in tables and "t2" not in tables and "t3" not in tables
    # Fixing the bad file lets migration resume cleanly.
    _write(migdir, 2, "bad", "CREATE TABLE t2(id TEXT PRIMARY KEY);")
    assert runner.migrate() == 3


def test_sqlite_storage_wires_repo_migrations(tmp_path: Path):
    """End-to-end through SQLiteStorage: repo migrations/ applies cleanly."""
    store = SQLiteStorage(tmp_path / "db.sqlite", tmp_path / "artifacts")
    try:
        v = store.migrate()
        assert v >= 1
        # Insert + read a record to prove the schema is live.
        rid = store.insert_record("campaign", "c-1", {"name": "demo"})
        assert rid == "c-1"
        # Re-migrate is a no-op.
        assert store.migrate() == v
        # Applied history carries hashes → corruption detection is armed.
        runner_rows = store.conn.execute("SELECT version, sha256 FROM schema_migrations").fetchall()
        assert all(r["sha256"] for r in runner_rows)
    finally:
        store.close()


def test_data_preserved_across_versions(tmp_path: Path, migdir: Path):
    """§21 acceptance shape: state written at v1 still readable at v2."""
    _write(migdir, 1, "v1", "CREATE TABLE items(id INTEGER PRIMARY KEY, val TEXT);")
    d = tmp_path / "data"
    d.mkdir()
    db_path = d / "x.db"
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    r1 = MigrationRunner(conn, migdir)
    r1.migrate()
    conn.execute("INSERT INTO items (id, val) VALUES (1, 'precious')")
    conn.commit()

    _write(migdir, 2, "v2", "ALTER TABLE items ADD COLUMN tag TEXT DEFAULT '';")
    r2 = MigrationRunner(conn, migdir)
    r2.migrate()
    row = conn.execute("SELECT id, val, tag FROM items WHERE id=1").fetchone()
    assert (row["id"], row["val"], row["tag"]) == (1, "precious", "")
