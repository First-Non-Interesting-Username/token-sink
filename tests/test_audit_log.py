"""Tests for the tamper-evident audit log (PLAN §14/§15, issue #177)."""

from __future__ import annotations

import json
import sqlite3

import pytest

from observability.audit_log import (
    GENESIS_HASH,
    AuditEventClass,
    AuditLog,
)


@pytest.fixture()
def audit(tmp_path):
    conn = sqlite3.connect(tmp_path / "audit.db")
    conn.row_factory = sqlite3.Row
    log = AuditLog(conn)
    yield log, conn
    conn.close()


def _sample(audit: AuditLog, n: int = 5) -> list:
    return [
        audit.append(
            f"test.action_{i}",
            actor_type="agent",
            actor_id=f"agent-{i}",
            correlation_id="c-1",
            payload={"i": i},
        )
        for i in range(n)
    ]


def test_append_only_enforced_at_storage_layer(audit):
    log, conn = audit
    entry = log.append("x", actor_type="system", actor_id="core")
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("UPDATE audit_log SET action='tampered' WHERE seq=?", (entry.seq,))
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("DELETE FROM audit_log WHERE seq=?", (entry.seq,))


def test_chain_links_and_head_persisted(audit):
    log, _ = audit
    entries = _sample(log)
    assert len(entries) > 1
    assert entries[0].prev_hash == GENESIS_HASH
    for prev, cur in zip(entries, entries[1:] if len(entries) > 1 else [], strict=False):
        assert cur.prev_hash == prev.hash
    seq, head_hash = log.head()
    assert (seq, head_hash) == (entries[-1].seq, entries[-1].hash)


def test_verify_clean_log(audit):
    log, _ = audit
    result = log.verify()
    assert result.ok is True
    assert result.total_entries == 0
    _sample(log, 7)
    result = log.verify()
    assert result.ok and result.total_entries == 7


def test_verify_detects_edited_payload(audit):
    log, conn = audit
    _sample(log, 3)
    # Simulate a direct file-level edit bypassing the API (as if the DB file
    # was opened externally): disable the guard trigger like a raw editor would.
    conn.execute("DROP TRIGGER audit_log_no_update")
    conn.execute("UPDATE audit_log SET payload='{\"evil\": true}' WHERE seq=2")
    conn.execute(
        "CREATE TRIGGER audit_log_no_update BEFORE UPDATE ON audit_log"
        " BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;"
    )
    result = log.verify()
    assert not result.ok
    assert result.entry_seq == 2  # first corrupted entry reported


def test_verify_detects_deleted_middle_entry(audit):
    log, conn = audit
    _sample(log, 5)
    conn.execute("DROP TRIGGER audit_log_no_delete")
    conn.execute("DELETE FROM audit_log WHERE seq=3")
    result = log.verify()
    assert not result.ok
    assert "gap" in result.reason


def test_verify_detects_deleted_tail_entries_via_persisted_head(audit):
    log, conn = audit
    _sample(log, 5)
    # Delete the newest entries — a pure prev-hash chain cannot see this,
    # but the persisted head in the separate table can.
    conn.execute("DROP TRIGGER audit_log_no_delete")
    conn.execute("DELETE FROM audit_log WHERE seq >= 4")
    result = log.verify()
    assert not result.ok
    assert "deleted" in result.reason


def test_concurrent_writers_keep_chain_linearizable(audit):
    """Two connections appending 'simultaneously' must serialize: the second
    append sees the first's committed head (BEGIN IMMEDIATE + head read inside
    the transaction guarantees a single linear order with no forked chain)."""
    log_a, conn_a = audit
    # Same underlying DB via a second file handle: exercises the
    # BEGIN IMMEDIATE serialization path across writers.
    db_file = conn_a.execute("PRAGMA database_list").fetchone()[2]
    conn_b = sqlite3.connect(db_file)
    conn_b.row_factory = sqlite3.Row

    e1 = log_a.append("a.op", actor_type="system", actor_id="A")
    log_b = AuditLog(conn_b)
    e2 = log_b.append("b.op", actor_type="system", actor_id="B")
    assert e2.prev_hash == e1.hash  # chained onto A's entry, not genesis
    assert len(log_a.entries()) == 2
    assert log_a.verify().ok


def test_every_mandatory_event_class_is_recorded(audit):
    """Each mandatory class from issue #177 appears as an asserted record."""
    log, _ = audit
    for action in AuditEventClass.ALL:
        entry = log.append(
            action,
            actor_type="system",
            actor_id="core",
            correlation_id=f"corr-{action}",
            payload={"mandatory": True},
        )
        stored = log.get(entry.seq)
        assert stored is not None and stored.action == action
    # And they round-trip through the filter API.
    for action in AuditEventClass.ALL:
        assert [e.action for e in log.entries(action=action)] == [action]
    assert log.verify().ok


def test_no_prune_method_retention_exempt(audit):
    """Retention pruning (#52) must never touch the audit log: the class has
    no prune/delete surface at all."""
    log, _ = audit
    _sample(log, 3)
    assert not hasattr(log, "prune") and not hasattr(log, "delete")


def test_export_preserves_verifiability(audit):
    log, _ = audit
    _sample(log, 4)
    _, head_hash = log.head()
    rows = list(log.export_entries())
    # Recompute the chain exactly as verify() would over the export.
    expected_prev = GENESIS_HASH
    for r in rows:
        assert r["prev_hash"] == expected_prev
        canonical = json.dumps(
            {
                k: r[k]
                for k in (
                    "seq",
                    "ts",
                    "actor_type",
                    "actor_id",
                    "action",
                    "correlation_id",
                    "payload",
                    "prev_hash",
                )
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        from observability.audit_log import _chain_hash

        expected_prev = _chain_hash(expected_prev, canonical)
        assert expected_prev == r["hash"]
    assert expected_prev == head_hash  # export verifies against exported head
