"""Migration discovery.

Each migration lives in ``mavr/migrations/versions/`` as a file named
``NNNN_name.sql``. A ``-- +mavr down`` sentinel line splits the file into
up SQL (above) and down SQL (below).
"""
from __future__ import annotations

import hashlib
import re
import sqlite3
from dataclasses import dataclass
from pathlib import Path

VERSIONS_DIR = Path(__file__).parent / "versions"
_DOWN_SENTINEL = re.compile(r"^--\s*\+mavr\s+down\s*$", re.MULTILINE)


@dataclass(frozen=True)
class Migration:
    version: int
    name: str
    sql: str
    down_sql: str | None
    checksum: str

    @property
    def filename(self) -> str:
        return f"{self.version:04d}_{self.name}.sql"


def _split(sql: str) -> tuple[str, str | None]:
    m = _DOWN_SENTINEL.search(sql)
    if not m:
        return sql, None
    return sql[: m.start()].rstrip() + "\n", sql[m.end():].lstrip() or None


def discover_migrations() -> list[Migration]:
    out: list[Migration] = []
    if not VERSIONS_DIR.exists():
        return out
    for path in sorted(VERSIONS_DIR.glob("*.sql")):
        m = re.match(r"^(\d{4,})_(.+)\.sql$", path.name)
        if not m:
            continue
        version = int(m.group(1))
        name = m.group(2)
        text = path.read_text(encoding="utf-8")
        up_sql, down_sql = _split(text)
        checksum = hashlib.sha256(text.encode("utf-8")).hexdigest()
        out.append(Migration(version=version, name=name, sql=up_sql, down_sql=down_sql, checksum=checksum))
    return out


def list_tables(conn: sqlite3.Connection) -> list[str]:
    cur = conn.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
    return [row[0] for row in cur.fetchall()]
