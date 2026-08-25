"""aiosqlite-backed metadata database.

Connection management, a tiny migration runner, and a small set of
helpers. The DB file path is configured via :class:`mavr.config.loader`.
"""
from __future__ import annotations

import asyncio
import hashlib
import re
import sqlite3
from collections.abc import AsyncIterator, Iterable, Sequence
from contextlib import asynccontextmanager
from datetime import UTC
from pathlib import Path
from typing import Any

import aiosqlite

from mavr.migrations import discover_migrations
from mavr.observability.logging import get_logger

log = get_logger(__name__)

_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")


def expand_db_path(path: str) -> Path:
    p = Path(path).expanduser().resolve()
    p.parent.mkdir(parents=True, exist_ok=True)
    return p


class Database:
    """Thin async wrapper over aiosqlite."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = asyncio.Lock()

    async def connect(self) -> aiosqlite.Connection:
        conn = await aiosqlite.connect(self.path)
        conn.row_factory = sqlite3.Row
        await conn.execute("PRAGMA foreign_keys = ON")
        await conn.execute("PRAGMA journal_mode = WAL")
        await conn.execute("PRAGMA synchronous = NORMAL")
        return conn

    @asynccontextmanager
    async def acquire(self) -> AsyncIterator[aiosqlite.Connection]:
        async with self._lock:
            conn = await self.connect()
            try:
                yield conn
            finally:
                await conn.close()

    async def execute(self, sql: str, params: Sequence[Any] = ()) -> aiosqlite.Cursor:
        async with self.acquire() as conn:
            cur = await conn.execute(sql, params)
            await conn.commit()
            return cur

    async def executemany(self, sql: str, seq: Iterable[Sequence[Any]]) -> aiosqlite.Cursor:
        async with self.acquire() as conn:
            cur = await conn.executemany(sql, seq)
            await conn.commit()
            return cur

    async def fetchone(self, sql: str, params: Sequence[Any] = ()) -> sqlite3.Row | None:
        async with self.acquire() as conn:
            cur = await conn.execute(sql, params)
            return await cur.fetchone()

    async def fetchall(self, sql: str, params: Sequence[Any] = ()) -> list[sqlite3.Row]:
        async with self.acquire() as conn:
            cur = await conn.execute(sql, params)
            return list(await cur.fetchall())

    async def ping(self) -> tuple[bool, str]:
        try:
            async with self.acquire() as conn:
                await conn.execute("SELECT 1")
            return True, f"db reachable: {self.path}"
        except (OSError, sqlite3.DatabaseError) as exc:
            return False, f"db error: {exc}"


# ---- migrations ----------------------------------------------------------


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


async def ensure_migrations_table(conn: aiosqlite.Connection) -> None:
    await conn.execute(
        """
        CREATE TABLE IF NOT EXISTS schema_migrations (
            version    INTEGER PRIMARY KEY,
            name       TEXT NOT NULL,
            applied_at TEXT NOT NULL,
            checksum   TEXT NOT NULL
        )
        """
    )


async def applied_versions(conn: aiosqlite.Connection) -> dict[int, str]:
    await ensure_migrations_table(conn)
    cur = await conn.execute("SELECT version, checksum FROM schema_migrations")
    return {row["version"]: row["checksum"] for row in await cur.fetchall()}


async def apply_migrations(db: Database, direction: str = "up") -> list[int]:
    """Apply pending migrations.

    ``direction`` is ``up`` (apply) or ``down`` (revert all, for tests).
    Returns the list of versions touched.
    """
    migrations = discover_migrations()
    if not migrations:
        return []
    async with db.acquire() as conn:
        await ensure_migrations_table(conn)
        await conn.execute("BEGIN")
        try:
            applied = await applied_versions(conn)
            touched: list[int] = []
            if direction == "up":
                for m in migrations:
                    if m.version in applied:
                        if applied[m.version] != m.checksum:
                            raise RuntimeError(
                                f"migration {m.version} has a checksum mismatch; "
                                "the SQL file has been modified after apply"
                            )
                        continue
                    log.info("migration_apply", version=m.version, name=m.name)
                    await conn.executescript(m.sql)
                    await conn.execute(
                        "INSERT INTO schema_migrations(version, name, applied_at, checksum) "
                        "VALUES (?, ?, ?, ?)",
                        (m.version, m.name, _now_iso(), m.checksum),
                    )
                    touched.append(m.version)
            elif direction == "down":
                # revert in reverse order, but only what we actually applied
                applied_list = sorted(applied.keys(), reverse=True)
                for version in applied_list:
                    matches = [x for x in migrations if x.version == version]
                    if not matches:
                        continue
                    m = matches[0]
                    if not m.down_sql:
                        continue
                    if m is None or not m.down_sql:
                        continue
                    log.info("migration_revert", version=version, name=m.name)
                    await conn.executescript(m.down_sql)
                    await conn.execute(
                        "DELETE FROM schema_migrations WHERE version = ?", (version,)
                    )
                    touched.append(version)
            else:
                raise ValueError(f"unknown migration direction: {direction!r}")
            await conn.commit()
        except Exception:
            await conn.rollback()
            raise
    return touched


# ---- misc ----------------------------------------------------------------


def _now_iso() -> str:
    from datetime import datetime

    return datetime.now(UTC).isoformat()


def is_uuid(value: str) -> bool:
    return bool(_UUID_RE.match(value))


def is_sha256_hex(value: str) -> bool:
    return bool(_HEX64_RE.match(value))
