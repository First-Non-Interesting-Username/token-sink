"""SQLite implementation of the Storage interface (PLAN.md §12).

Why SQLite for Phase 1: local-first, transactional, zero-config; the
`Storage` interface keeps engines swappable later.

Artifact layout: content-addressed two-level fanout (artifacts/ab/cd/<sha256>),
which avoids any filesystem with too-many-files-per-dir problems and makes the
stored path independent of user-supplied names — filename is metadata, hash is
identity. Path traversal is impossible by construction because paths are
derived from hex digests only.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from pathlib import Path
from typing import Any

from storage.base import (
    ArtifactNotFoundError,
    ConflictError,
    RecordExistsError,
    Storage,
)

# Migrations moved to file-based forward-only runner (issue #130): see
# storage/migrations.py and migrations/*.sql. Kept here only as a re-export
# for backwards compatibility with older imports.
from storage.migrations import Migration, MigrationError, MigrationRunner  # noqa: E402,F401

# Repo-shipped migrations live at the project root (PLAN §4 layout).
_DEFAULT_MIGRATIONS_DIR = Path(__file__).resolve().parent.parent / "migrations"

_SAFE_ID = re.compile(r"^[A-Za-z0-9._:@-]{1,256}$")


class SQLiteStorage(Storage):
    def __init__(
        self,
        db_path: str | Path,
        artifact_dir: str | Path,
        migrations_dir: str | Path | None = None,
    ):
        self.db_path = Path(db_path)
        self.artifact_dir = Path(artifact_dir)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.artifact_dir.mkdir(parents=True, exist_ok=True)
        # WAL mode: readers don't block writers and a crashed process leaves a
        # recoverable log instead of a half-written main DB file.
        self.conn = sqlite3.connect(self.db_path, isolation_level=None)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.conn.row_factory = sqlite3.Row
        # Migrations dir defaults to the repo's migrations/ package sibling;
        # overridable for tests that exercise synthetic migration sequences.
        self.migrations_dir = Path(migrations_dir) if migrations_dir else _DEFAULT_MIGRATIONS_DIR
        self._runner: MigrationRunner | None = None
        self._runner_migrations_dir = ""

    # --- lifecycle / migrations ---

    def close(self) -> None:
        self.conn.close()

    @property
    def schema_version(self) -> int:
        self._ensure_migration_table()
        row = self.conn.execute("SELECT MAX(version) AS v FROM schema_migrations").fetchone()
        return row["v"] or 0

    def migrate(self) -> int:
        """Apply pending migrations via the shared forward-only runner.

        The runner enforces the safety properties from issue #130 / PLAN §12:
        content-hash verification of applied history, downgrade protection,
        one transaction per migration (crash-safe), and gap detection.
        """
        self._ensure_migration_table()
        if self._runner is None or self._runner_migrations_dir != str(self.migrations_dir):
            self._runner = MigrationRunner(self.conn, self.migrations_dir)
            self._runner_migrations_dir = str(self.migrations_dir)
        return self._runner.migrate()

    def _ensure_migration_table(self) -> None:
        # Kept as a minimal standalone create so schema_version can be read
        # before any MigrationRunner exists (e.g. doctor checks). The runner
        # creates the richer history table (name/sha256 columns) itself.
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS schema_migrations ("
            " version INTEGER PRIMARY KEY,"
            " applied_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')))"
        )
        if not hasattr(self, "_migration_table_ready"):
            self.conn.commit()
            self._migration_table_ready = True

    # --- helpers ---

    @staticmethod
    def _check_id(record_id: str) -> None:
        # IDs become part of SQL params (safe) but also appear in logs/exports;
        # constraining shape here keeps downstream consumers simple.
        if not isinstance(record_id, str) or not _SAFE_ID.match(record_id):
            raise ValueError(f"invalid record id: {record_id!r}")

    @staticmethod
    def _row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
        d = dict(row)
        d["data"] = json.loads(d["data"])
        return d

    # --- records ---

    def insert_record(
        self, kind: str, record_id: str, data: dict[str, Any], idempotency_key: str | None = None
    ) -> str:
        self._check_id(record_id)
        try:
            with self.conn:
                self.conn.execute(
                    "INSERT INTO records (kind, id, data, idempotency_key) VALUES (?, ?, ?, ?)",
                    (kind, record_id, json.dumps(data), idempotency_key),
                )
        except sqlite3.IntegrityError as e:
            raise RecordExistsError(
                f"{kind}/{record_id} already exists (or idempotency key reused): {e}"
            ) from e
        return record_id

    def get_record(self, kind: str, record_id: str) -> dict[str, Any] | None:
        row = self.conn.execute(
            "SELECT * FROM records WHERE kind=? AND id=?", (kind, record_id)
        ).fetchone()
        return self._row_to_dict(row) if row else None

    def update_record(
        self, kind: str, record_id: str, expected_version: int, patch: dict[str, Any]
    ) -> dict[str, Any]:
        self._check_id(record_id)
        with self.conn:
            row = self.conn.execute(
                "SELECT data, version FROM records WHERE kind=? AND id=?", (kind, record_id)
            ).fetchone()
            if row is None:
                raise KeyError(f"{kind}/{record_id} not found")
            if row["version"] != expected_version:
                raise ConflictError(
                    f"{kind}/{record_id}: expected version {expected_version}, "
                    f"current is {row['version']}"
                )
            merged = {**json.loads(row["data"]), **patch}
            cur = self.conn.execute(
                "UPDATE records SET data=?, version=version+1,"
                " updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now')"
                " WHERE kind=? AND id=? AND version=?",
                (json.dumps(merged), kind, record_id, expected_version),
            )
            assert cur.rowcount == 1  # guarded by the SELECT above inside the txn
        return self.get_record(kind, record_id)  # type: ignore[return-value]

    def list_records(self, kind: str, limit: int = 100) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT * FROM records WHERE kind=? ORDER BY updated_at DESC LIMIT ?", (kind, limit)
        ).fetchall()
        return [self._row_to_dict(r) for r in rows]

    # --- atomic state transitions ---

    def transition(
        self, kind: str, record_id: str, from_state: str | None, to_state: str, reason: str = ""
    ) -> None:
        self._check_id(record_id)
        with self.conn:
            # Single UPDATE guarded by the expected from_state makes the check
            # and the write one atomic operation (no TOCTOU between them).
            if from_state is None:
                cur = self.conn.execute(
                    "UPDATE records SET state=?,"
                    " updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now')"
                    " WHERE kind=? AND id=?",
                    (to_state, kind, record_id),
                )
            else:
                cur = self.conn.execute(
                    "UPDATE records SET state=?,"
                    " updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now')"
                    " WHERE kind=? AND id=? AND state=?",
                    (to_state, kind, record_id, from_state),
                )
            if cur.rowcount != 1:
                row = self.conn.execute(
                    "SELECT state FROM records WHERE kind=? AND id=?", (kind, record_id)
                ).fetchone()
                actual = row["state"] if row else "<missing>"
                raise ConflictError(
                    f"cannot transition {kind}/{record_id}: "
                    f"expected state {from_state!r}, actual {actual!r}"
                )
            self.conn.execute(
                "INSERT INTO transitions (kind, record_id, from_state, to_state, reason)"
                " VALUES (?, ?, ?, ?, ?)",
                (kind, record_id, from_state, to_state, reason),
            )

    def get_transitions(self, kind: str, record_id: str) -> list[dict[str, Any]]:
        """Read a record's append-only transition history."""
        rows = self.conn.execute(
            "SELECT * FROM transitions WHERE kind=? AND record_id=? ORDER BY seq", (kind, record_id)
        ).fetchall()
        return [dict(r) for r in rows]

    # --- artifacts ---

    def put_artifact(self, data: bytes, suggested_name: str = "artifact.bin") -> tuple[str, str]:
        sha = hashlib.sha256(data).hexdigest()
        # Two-level fanout derived purely from the hex digest — no user input
        # ever reaches the path, so traversal is structurally impossible.
        rel = f"{sha[:2]}/{sha[2:4]}/{sha}"
        dest = self.artifact_dir / rel
        if not dest.exists():  # idempotent: same bytes -> same path, no rewrite
            dest.parent.mkdir(parents=True, exist_ok=True)
            tmp = dest.with_suffix(".tmp")  # write-then-rename = no torn files
            tmp.write_bytes(data)
            tmp.rename(dest)
        with self.conn:
            self.conn.execute(
                "INSERT OR IGNORE INTO artifacts (sha256, size, suggested_name) VALUES (?, ?, ?)",
                (sha, len(data), suggested_name),
            )
        return sha, rel

    def get_artifact(self, sha256: str) -> bytes:
        if not re.fullmatch(r"[0-9a-f]{64}", sha256):
            raise ArtifactNotFoundError(f"malformed artifact hash: {sha256!r}")
        path = self.artifact_dir / sha256[:2] / sha256[2:4] / sha256
        if not path.exists():
            raise ArtifactNotFoundError(sha256)
        data = path.read_bytes()
        # Verify checksum on every read: catches silent corruption/tampering
        # rather than returning untrusted bytes.
        if hashlib.sha256(data).hexdigest() != sha256:
            raise ArtifactNotFoundError(f"checksum mismatch for {sha256}")
        return data

    # --- backup / export / import (PLAN §12) ---

    def export_all(self) -> dict[str, Any]:
        """Full logical export: every table as JSON. Used by backup and tests."""
        out: dict[str, Any] = {"schema_version": self.schema_version, "tables": {}}
        for table in ("records", "transitions", "artifacts", "schema_migrations"):
            rows = self.conn.execute(f"SELECT * FROM {table}").fetchall()  # noqa: S608 — fixed name
            out["tables"][table] = [dict(r) for r in rows]
        return out
