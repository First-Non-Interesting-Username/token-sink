# Tamper-evident audit log (PLAN §14/§15, issue #177)

Implementation: `observability/audit_log.py` (`AuditLog` over SQLite).
Companion doc to `docs/event-store.md` — the two are deliberately separate:

| | Event store (`event_store.py`) | Audit log (`audit_log.py`) |
|---|---|---|
| Purpose | real-time UI streaming, replay, retention | compliance record of security-relevant actions |
| Retention | prunable (gap anchors keep chain verifiable) | **exempt from pruning** — no prune API exists |
| Tamper evidence | per-campaign prev-hash chain | hash chain + externally persisted head + storage-layer write guards |

## Design decisions

- **Append-only enforced twice.** The Python class exposes only `append`
  and read APIs; additionally SQLite triggers (`audit_log_no_update`,
  `audit_log_no_delete`) abort any raw UPDATE/DELETE — even from another
  process opening the DB file directly.
- **Hash chain.** Each entry commits to `seq`, `ts`, actor, action,
  correlation id, payload and the previous entry's hash
  (`AuditEntry.canonical()` defines the canonical serialization). Editing any
  entry breaks every link after it.
- **Persisted chain head in a separate table.** A pure prev-hash chain cannot
  detect deletion of the newest entries. `audit_head` stores the head
  `(seq, hash)` outside the log rows, updated in the same transaction as the
  insert, so `verify()` catches tail deletions too ("head records seq N but
  only M entries exist").
- **verify() reports the first bad entry**: edited entry → its seq; deleted
  middle entry → gap reason with expected linkage; deleted tail / empty log →
  head-mismatch reason.
- **Linearizable concurrent appends**: the head is read inside a
  `BEGIN IMMEDIATE` transaction, so simultaneous writers serialize onto one
  chain instead of forking it.
- **Retention interplay (#52/#57)**: audit rows are exempt from ordinary
  pruning; secure-deletion controls do not apply. `export_entries()` yields
  JSON-ready entries that re-verify against the exported head hash.

## Mandatory event classes

`AuditEventClass.ALL` lists what MUST be audited: approvals
(granted/denied/expired), blocked policy actions, kill-switch engagement,
scope changes, finding deletion/quarantine, submission attempts.
`tests/test_audit_log.py::test_every_mandatory_event_class_is_recorded`
asserts each one produces an auditable record — extend both together.

## Usage

```python
from observability.audit_log import AuditLog

log = AuditLog(conn)
entry = log.append(
    AuditEventClass.APPROVAL_GRANTED,
    actor_type="human",  # 'human' | 'agent' | 'system'
    actor_id="operator",
    correlation_id="campaign-x:req-42",
    payload={"po_id": "poc-7"},
)
result = log.verify()
assert result.ok
```

A `system logs --verify` CLI wrapper lands with the diagnostics command work
(#93/#145); the verification core above is the source of truth.
