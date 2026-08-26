"""Tamper-evident audit log (PLAN §14/§15, issue #177).

Distinct from the campaign event store (``observability/event_store.py``):
the event store serves real-time UI streaming with retention/pruning; the
audit log is a *compliance* record of security-relevant actions. Its
guarantees are intentionally stricter:

- **Append-only at the storage layer**: no update/delete API exists, and the
  SQLite schema uses triggers to reject UPDATE/DELETE even from raw SQL.
- **Hash-chained entries**: each entry commits to ``seq``, the previous
  entry's hash and its own payload — editing any entry breaks every chain
  link after it.
- **Externally persisted chain head**: the head hash is stored in a separate
  ``audit_head`` table (and can be exported/offline-copied). Because the
  head lives *outside* the log rows, deleting the newest entries — which a
  pure prev-hash chain cannot detect — is caught by comparing against the
  recorded head.
- **Retention-exempt**: ordinary pruning (#52) must never touch audit rows;
  there is deliberately no prune method. Secure-deletion controls do not
  apply either.

Mandatory event classes are defined as constants in :class:`AuditEventClass`
so tests and call sites fail loudly if a class disappears.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any


class AuditEventClass:
    """Event classes that MUST be audited (issue #177 / PLAN §15).

    Tests assert each of these appears with an asserted audit record; keep
    them stable — they are part of the compliance surface.
    """

    APPROVAL_GRANTED = "approval.granted"
    APPROVAL_DENIED = "approval.denied"
    APPROVAL_EXPIRED = "approval.expired"
    POLICY_ACTION_BLOCKED = "policy.action_blocked"
    KILL_SWITCH_ENGAGED = "kill_switch.engaged"
    SCOPE_CHANGED = "scope.changed"
    FINDING_DELETED = "finding.deleted"
    FINDING_QUARANTINED = "finding.quarantined"
    SUBMISSION_ATTEMPTED = "submission.attempted"

    ALL = (
        APPROVAL_GRANTED,
        APPROVAL_DENIED,
        APPROVAL_EXPIRED,
        POLICY_ACTION_BLOCKED,
        KILL_SWITCH_ENGAGED,
        SCOPE_CHANGED,
        FINDING_DELETED,
        FINDING_QUARANTINED,
        SUBMISSION_ATTEMPTED,
    )


GENESIS_HASH = hashlib.sha256(b"token-sink:audit-log:genesis").hexdigest()

_SCHEMA_TEMPLATE = """CREATE TABLE IF NOT EXISTS audit_log (
    seq INTEGER PRIMARY KEY,
    ts TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    actor_type TEXT NOT NULL CHECK (actor_type IN ('human', 'agent', 'system')),
    actor_id TEXT NOT NULL,
    action TEXT NOT NULL,
    correlation_id TEXT NOT NULL DEFAULT '',
    payload_hash TEXT NOT NULL,
    payload TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    hash TEXT NOT NULL UNIQUE
);
CREATE TABLE IF NOT EXISTS audit_head (
    id INTEGER PRIMARY KEY CHECK (id = 1),   -- singleton row
    seq INTEGER NOT NULL DEFAULT 0,
    hash TEXT NOT NULL
);
INSERT OR IGNORE INTO audit_head (id, seq, hash) VALUES (1, 0, '__GENESIS__');
-- Tamper resistance at the storage layer: even raw SQL may not mutate or
-- delete committed audit rows. The append path drops/recreates the trigger
-- inside its transaction only.
CREATE TRIGGER IF NOT EXISTS audit_log_no_update BEFORE UPDATE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_log_no_delete BEFORE DELETE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
"""


@dataclass(frozen=True)
class AuditEntry:
    """One tamper-evident audit record."""

    seq: int  # monotonic, gap-free, starts at 1
    ts: str
    actor_type: str  # 'human' | 'agent' | 'system'
    actor_id: str  # username, agent UUID, or component name
    action: str  # one of AuditEventClass values or another auditable action
    correlation_id: str  # ties the entry to the request/campaign trace
    payload: dict[str, Any]
    prev_hash: str
    hash: str

    def canonical(self) -> str:
        """Canonical serialization covered by the chain hash."""
        return json.dumps(
            {
                "seq": self.seq,
                "ts": self.ts,
                "actor_type": self.actor_type,
                "actor_id": self.actor_id,
                "action": self.action,
                "correlation_id": self.correlation_id,
                "payload": self.payload,
                "prev_hash": self.prev_hash,
            },
            sort_keys=True,
            separators=(",", ":"),
        )


def _chain_hash(prev_hash: str, canonical: str) -> str:
    return hashlib.sha256((prev_hash + canonical).encode("utf-8")).hexdigest()


def _payload_hash(payload: dict[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


@dataclass(frozen=True)
class VerifyResult:
    """Outcome of walking the full audit chain."""

    ok: bool
    total_entries: int = 0
    # First bad entry, when verification failed. ``expected_prev_hash`` is
    # what the chain says should be there; a None entry_seq with entries
    # present means the log itself has a gap (deleted middle entry).
    entry_seq: int | None = None
    reason: str = ""
    expected_prev_hash: str = ""


class AuditLog:
    """SQLite-backed append-only, hash-chained audit log."""

    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn
        conn.executescript(_SCHEMA_TEMPLATE.replace("__GENESIS__", GENESIS_HASH))

    # -- append -----------------------------------------------------------

    def append(
        self,
        action: str,
        *,
        actor_type: str,
        actor_id: str,
        correlation_id: str = "",
        payload: dict[str, Any] | None = None,
    ) -> AuditEntry:
        """Append one audit entry atomically with the chain-head update.

        The head row lives in a separate table updated in the SAME
        transaction, so a crash can never leave the head disagreeing with
        the last appended entry.
        """
        if actor_type not in ("human", "agent", "system"):
            raise ValueError(f"invalid actor_type: {actor_type!r}")
        if not isinstance(action, str) or not action:
            raise ValueError("action must be a non-empty string")

        head_seq, head_hash = self.head()
        seq = head_seq + 1
        ts_sql = "strftime('%Y-%m-%dT%H:%M:%fZ','now')"
        payload = payload or {}

        # Compute the canonical form with a placeholder ts first? No — the
        # timestamp comes from SQLite's clock, so we read it explicitly to
        # build the canonical form deterministically.
        row = self.conn.execute(f"SELECT {ts_sql} AS ts").fetchone()
        ts = row["ts"]
        prev_hash = head_hash
        entry = AuditEntry(
            seq=seq,
            ts=ts,
            actor_type=actor_type,
            actor_id=actor_id,
            action=action,
            correlation_id=correlation_id,
            payload=payload,
            prev_hash=prev_hash,
            hash="",
        )
        entry = AuditEntry(**{**entry.__dict__, "hash": _chain_hash(prev_hash, entry.canonical())})

        # Single transaction: insert row + bump head + temporarily lift the
        # append-only guard for exactly this INSERT (the guard blocks
        # UPDATE/DELETE only, so it can stay enabled for the insert).
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            self.conn.execute(
                "INSERT INTO audit_log (seq, ts, actor_type, actor_id, action,"
                " correlation_id, payload_hash, payload, prev_hash, hash)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    entry.seq,
                    entry.ts,
                    entry.actor_type,
                    entry.actor_id,
                    entry.action,
                    entry.correlation_id,
                    _payload_hash(entry.payload),
                    json.dumps(entry.payload, sort_keys=True, separators=(",", ":")),
                    entry.prev_hash,
                    entry.hash,
                ),
            )
            self.conn.execute(
                "UPDATE audit_head SET seq = ?, hash = ? WHERE id = 1",
                (entry.seq, entry.hash),
            )
            self.conn.execute("COMMIT")
        except BaseException:
            if self.conn.in_transaction:
                self.conn.execute("ROLLBACK")
            raise
        return entry

    # -- read -------------------------------------------------------------

    def head(self) -> tuple[int, str]:
        """(seq, hash) of the externally-persisted chain head."""
        row = self.conn.execute("SELECT seq, hash FROM audit_head WHERE id = 1").fetchone()
        return row["seq"], row["hash"]

    def get(self, seq: int) -> AuditEntry | None:
        row = self.conn.execute("SELECT * FROM audit_log WHERE seq = ?", (seq,)).fetchone()
        return self._row_to_entry(row) if row else None

    def entries(
        self,
        *,
        action: str | None = None,
        correlation_id: str | None = None,
        limit: int = 1000,
    ) -> list[AuditEntry]:
        """Ordered entries, optionally filtered. Read-only convenience."""
        q = "SELECT * FROM audit_log"
        conds, params = [], []
        if action is not None:
            conds.append("action = ?")
            params.append(action)
        if correlation_id is not None:
            conds.append("correlation_id = ?")
            params.append(correlation_id)
        if conds:
            q += " WHERE " + " AND ".join(conds)
        q += " ORDER BY seq LIMIT ?"
        params.append(limit)
        return [self._row_to_entry(r) for r in self.conn.execute(q, params).fetchall()]

    @staticmethod
    def _row_to_entry(row: sqlite3.Row) -> AuditEntry:
        return AuditEntry(
            seq=row["seq"],
            ts=row["ts"],
            actor_type=row["actor_type"],
            actor_id=row["actor_id"],
            action=row["action"],
            correlation_id=row["correlation_id"],
            payload=json.loads(row["payload"]),
            prev_hash=row["prev_hash"],
            hash=row["hash"],
        )

    # -- integrity ----------------------------------------------------------

    def verify(self) -> VerifyResult:
        """Walk the whole chain; report the first corrupted or missing entry.

        Detects three tamper classes:
        - edited entry (payload/hash mismatch or broken prev-link);
        - deleted middle entry (seq gap → chain linkage check fails);
        - deleted tail entries (rows end before the persisted head).
        """
        head_seq, head_hash = self.head()
        expected_prev = GENESIS_HASH
        expected_seq = 1
        count = 0
        for row in self.conn.execute("SELECT * FROM audit_log ORDER BY seq"):
            count += 1
            if row["seq"] != expected_seq:
                # A gap means middle entries were removed.
                return VerifyResult(
                    ok=False,
                    total_entries=count,
                    entry_seq=None,
                    reason=f"gap in audit log: expected seq {expected_seq}, found {row['seq']}",
                    expected_prev_hash=expected_prev,
                )
            entry = self._row_to_entry(row)
            recomputed = _chain_hash(expected_prev, entry.canonical())
            if row["prev_hash"] != expected_prev or recomputed != row["hash"]:
                return VerifyResult(
                    ok=False,
                    total_entries=count,
                    entry_seq=entry.seq,
                    reason="entry hash/prev-hash mismatch (edited or spliced entry)",
                    expected_prev_hash=expected_prev,
                )
            expected_prev = row["hash"]
            expected_seq += 1

        if count < head_seq:
            return VerifyResult(
                ok=False,
                total_entries=count,
                reason=(
                    f"chain head records seq {head_seq} but only {count} "
                    "entries exist — tail entries were deleted"
                ),
            )
        if count and expected_prev != head_hash:
            return VerifyResult(
                ok=False,
                total_entries=count,
                entry_seq=count,
                reason="persisted head hash does not match last entry",
            )
        if not count and head_seq:
            return VerifyResult(ok=False, reason="entire audit log deleted")
        return VerifyResult(ok=True, total_entries=count)

    # -- export ---------------------------------------------------------------

    def export_entries(self, first_seq: int = 1) -> Iterator[dict[str, Any]]:
        """Yield JSON-ready entries preserving chain verifiability.

        A consumer re-running verify() over an export plus the head hash
        (from ``head()``) gets the same guarantees as the live DB — used by
        the campaign bundle export (#57).
        """
        for row in self.conn.execute(
            "SELECT * FROM audit_log WHERE seq >= ? ORDER BY seq", (first_seq,)
        ):
            e = self._row_to_entry(row)
            yield {
                "seq": e.seq,
                "ts": e.ts,
                "actor_type": e.actor_type,
                "actor_id": e.actor_id,
                "action": e.action,
                "correlation_id": e.correlation_id,
                "payload": e.payload,
                "prev_hash": e.prev_hash,
                "hash": e.hash,
            }
