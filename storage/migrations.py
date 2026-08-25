"""Forward-only migration runner (PLAN.md §12, issue #130).

Design decisions (documented per AGENTS.md "document everything"):

- **Files over code**: migrations are ``.sql`` files under ``migrations/``,
  named ``NNN_description.sql``. The version is the leading number; the file
  content IS the migration. A sidecar table records the sha256 of each
  applied migration so hand-edited history fails loudly at startup instead of
  silently diverging from what was actually run.

- **Strictly forward-only**: there are no downgrades. Downgrading a live DB
  risks data loss and half-verified assumptions; instead the runner *refuses*
  to touch a database whose schema version is newer than the code knows
  (downgrade protection) — an old binary must never mis-read a new schema.

- **One transaction per migration**: SQLite DDL is transactional, so a crash
  mid-migration rolls back cleanly; the next startup re-applies it. The
  applied-version row commits in the SAME transaction as the DDL, so the
  "applied" marker can never exist without the schema change.

- **Explicit upgrade**: pending migrations are applied by calling
  :func:`MigrationRunner.migrate` (wired to ``system migrate``), not silently
  at import time — operators should see what will change before workers start.
"""

from __future__ import annotations

import hashlib
import re
import sqlite3
from dataclasses import dataclass
from pathlib import Path


def _split_statements(sql: str) -> list[str]:
    """Split a migration file into individual SQL statements.

    Deliberately minimal (split on ';' at end of statement): migrations are
    repo-controlled files, not user input, so a full tokenizer isn't needed.
    Comments and blank statements are dropped.
    """
    out = []
    buf: list[str] = []
    for line in sql.splitlines():
        stripped = line.strip()
        if not buf and (not stripped or stripped.startswith("--")):
            continue
        buf.append(line)
        if stripped.endswith(";"):
            stmt = "\n".join(buf).strip().rstrip(";").strip()
            # keep comment-only prefixes out of execution
            body = "\n".join(
                ln for ln in stmt.splitlines() if not ln.strip().startswith("--")
            ).strip()
            if body:
                out.append(body)
            buf = []
    tail = "\n".join(buf).strip()
    if tail:
        raise MigrationError(f"migration does not end with ';': {tail[:60]!r}")
    return out


class MigrationError(RuntimeError):
    """Raised for any unsafe/unexpected migration state."""


_FILENAME_RE = re.compile(r"^(\d{3})_([a-z0-9_]+)\.sql$")


@dataclass(frozen=True)
class Migration:
    version: int
    name: str
    sql: str
    sha256: str


def load_migrations(directory: str | Path) -> list[Migration]:
    """Load and validate all migration files. Gaps in numbering are rejected:
    a missing middle migration usually means a bad merge or partial copy."""
    directory = Path(directory)
    if not directory.is_dir():
        raise MigrationError(f"migrations directory not found: {directory}")
    found: dict[int, Migration] = {}
    for path in sorted(directory.iterdir()):
        if path.name == ".gitkeep":
            continue
        m = _FILENAME_RE.match(path.name)
        if not m:
            # Unknown filenames in migrations/ are a repo bug — fail loudly
            # rather than silently skipping something that might be a
            # hand-renamed migration.
            raise MigrationError(f"unexpected file in migrations/: {path.name}")
        sql = path.read_text(encoding="utf-8")
        version = int(m.group(1))
        if version in found:
            raise MigrationError(f"duplicate migration version {version}")
        found[version] = Migration(
            version=version,
            name=m.group(2),
            sql=sql,
            sha256=hashlib.sha256(sql.encode()).hexdigest(),
        )
    versions = sorted(found)
    for i, v in enumerate(versions):
        if v != versions[0] + i:
            raise MigrationError(f"migration version gap: expected {versions[0] + i}, found {v}")
    return [found[v] for v in versions]


class MigrationRunner:
    """Applies forward-only migrations to one SQLite connection."""

    def __init__(self, conn: sqlite3.Connection, migrations_dir: str | Path):
        self.conn = conn
        self.migrations_dir = Path(migrations_dir)
        # Loaded fresh on each public call (see _reload) so a long-running
        # process detects newly added migration files and — critically —
        # content changes to already-applied files at the next check.
        self.migrations: list[Migration] = []
        self._ensure_history_table()
        self._reload()

    def _reload(self) -> None:
        self.migrations = load_migrations(self.migrations_dir)

    # --- history table ---------------------------------------------------

    def _ensure_history_table(self) -> None:
        # Records which migration versions were applied AND their content
        # hash — the hash is what makes retroactive edits detectable.
        # CREATE TABLE IF NOT EXISTS won't add columns to a table created by
        # the older minimal schema (sqlite.py's _ensure_migration_table), so
        # migrate legacy tables explicitly and idempotently.
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS schema_migrations (
                version INTEGER PRIMARY KEY,
                name TEXT NOT NULL DEFAULT '',
                sha256 TEXT NOT NULL DEFAULT '',
                applied_at TEXT NOT NULL
                    DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
            )
            """
        )
        cols = {r["name"] for r in self.conn.execute("PRAGMA table_info(schema_migrations)")}
        if "name" not in cols:
            self.conn.execute(
                "ALTER TABLE schema_migrations ADD COLUMN name TEXT NOT NULL DEFAULT ''"
            )
        if "sha256" not in cols:
            self.conn.execute(
                "ALTER TABLE schema_migrations ADD COLUMN sha256 TEXT NOT NULL DEFAULT ''"
            )
        self.conn.commit()

    # --- introspection ----------------------------------------------------

    def applied(self) -> dict[int, str]:
        """version -> recorded sha256 of applied migrations."""
        rows = self.conn.execute(
            "SELECT version, sha256 FROM schema_migrations ORDER BY version"
        ).fetchall()
        return {r["version"]: r["sha256"] for r in rows}

    def current_version(self) -> int:
        rows = self.applied()
        return max(rows) if rows else 0

    def latest_version(self) -> int:
        return self.migrations[-1].version if self.migrations else 0

    def pending(self) -> list[Migration]:
        """Migrations not yet applied, in order (dry-run surface)."""
        current = self.current_version()
        return [m for m in self.migrations if m.version > current]

    def verify_history(self) -> None:
        """Fail loudly if applied history was edited or is inconsistent.

        Checks, in order of severity:
        - unknown-newer versions in the DB than the code ships → refuse to
          run against a future schema (downgrade protection);
        - recorded hash mismatch → someone edited an already-applied
          migration file (or the DB history);
        - applied versions that no longer exist as files → deleted history.
        """
        self._reload()
        applied = self.applied()
        known = {m.version: m.sha256 for m in self.migrations}
        for version, sha in applied.items():
            if version not in known:
                raise MigrationError(
                    f"database has schema version {version} but code only "
                    f"knows up to {self.latest_version()} — refusing to "
                    "operate on a newer schema (downgrade not supported)"
                )
            if known[version] != sha:
                raise MigrationError(
                    f"migration {version}: content hash mismatch — applied "
                    "history differs from the migration file on disk"
                )

    # -- application ---------------------------------------------------------

    def migrate(self) -> int:
        """Apply all pending migrations atomically; returns new version."""
        self.verify_history()  # also reloads migrations from disk
        for mig in self.pending():
            # sqlite3.executescript() issues an implicit COMMIT before running,
            # which would break atomicity — so we split statements and run them
            # inside an explicit transaction that also covers the history row.
            statements = [s for s in _split_statements(mig.sql) if s]
            try:
                self.conn.execute("BEGIN")
                for stmt in statements:
                    self.conn.execute(stmt)
                self.conn.execute(
                    "INSERT INTO schema_migrations (version, name, sha256) VALUES (?, ?, ?)",
                    (mig.version, mig.name, mig.sha256),
                )
            except sqlite3.Error as exc:
                if self.conn.in_transaction:
                    self.conn.execute("ROLLBACK")
                raise MigrationError(
                    f"migration {mig.version:03d}_{mig.name} failed: {exc}"
                ) from exc
            self.conn.execute("COMMIT")
        return self.current_version()
