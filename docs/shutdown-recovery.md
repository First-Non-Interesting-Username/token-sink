# Shutdown & Crash Recovery Protocol (PLAN §12, §18, §19.2)

Implements issue #136: the shutdown/recovery protocol that makes "restart must
not lose state" real. Code lives in `orchestrator/shutdown.py`; this doc is
the operator/agent-facing reference.

## Components

| Component | Purpose |
|---|---|
| `IntentJournal` | Write-ahead JSONL log of non-idempotent external side effects. `begin()` **before** the effect, `resolve()` after — recovery can then distinguish done vs not-done without guessing. |
| `ShutdownCoordinator` | SIGTERM/SIGINT handling: stops accepting new work (`accepting_work` gate), drains in-flight tasks within a bounded deadline, checkpoints whatever does not finish. |
| `recover()` | Startup sweep: resolves PENDING intents, releases stale leases, removes orphaned artifacts, logs every repair as a `RepairAction`. |

## Ordering rules

1. Record intent → run side effect → resolve intent. Never the reverse.
2. Shutdown: refuse new work first (`state = DRAINING`), then drain newest-
   registered callbacks first, hard deadline across all of them.
3. Recovery default policy for ambiguous intents is **abort**, not replay —
   a possibly-completed external effect must never be duplicated (#136).

## Crash safety properties

- Journal appends are fsync'd; a torn final line (kill -9 mid-write) is
  skipped on load.
- State changes append new lines; history stays auditable.
- Recovery is idempotent: resolved intents are not re-examined, lease release
  and artifact removal are no-ops when repeated. A crash *during* recovery
  resumes safely on the next start.

## Chaos tests

`tests/unit/test_shutdown.py` covers kill -9 simulation (abandoned journals,
torn writes), double-signal idempotency, deadline checkpointing, broken drain
hooks, and the no-duplicate-side-effects guarantee.
