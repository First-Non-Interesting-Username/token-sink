# Idempotent Task Execution (PLAN §12, issue #126)

Every side-effectful task step runs through `orchestrator.idempotency.ExecutionRunner`,
which journals intent *before* the effect and the result *after* it.

## How it works

1. **`runner.begin(task_id, execution_id)`** — one task has exactly one
   execution identity. Restarts MUST reuse the same `execution_id`; that is
   what makes dedupe work across crash/restart. A different execution id for
   an already-journalled task raises `DuplicateExecutionError`, and one
   execution id is permanently bound to its first task.
2. **`runner.run(execution_id, step, fn)`** — before calling `fn`, a step
   record is inserted with a UNIQUE idempotency key derived from
   `(execution_id, step)` and transitioned to `started`. After `fn` returns,
   the result is stored and the step transitions to `completed`. If
   `completed` already exists, `fn` is never called again — the journalled
   result is returned with `executed=False`.
3. **Crash between effect and completion write**: the next attempt sees
   `started` without `completed` and re-runs `fn`. Therefore **every callable
   passed to `run()` must itself be safe to re-run** — writes go through
   content-addressed artifacts (`put_artifact`) or storage calls carrying an
   idempotency key. This pairing (journal + re-runnable effects) gives
   exactly-once effects; see `tests/integration/test_idempotent_execution.py`.

## Why hashed ids

Journal record ids are SHA-256 prefixes of `execution_id:step` rather than raw
text, because the storage layer restricts ids to `_SAFE_ID` and arbitrary
task/step names shouldn't leak into DB ids shown in logs or exports.

## Uniqueness guarantees

Unique constraints for UUIDs/event IDs live at the DB level
(`records.idempotency_key UNIQUE` in migration v1), not in application code —
a duplicate event insert raises `storage.base.RecordExistsError`, which callers
treat as "already done".
