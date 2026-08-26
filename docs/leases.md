# Leases & stale-agent sweeping (`orchestrator/leases.py`)

Implements the lease/heartbeat/sweeper slice of PLAN §6 and §12 (issue #178).
This is where double-execution and lost-work bugs would live, so the
correctness model is deliberately simple:

## Model

- One **lease per task**, held by one agent. The lease carries an `epoch`
  that increments on every reassignment. An agent's capability to act is its
  token: `"{agent_uuid}:{epoch}"`.
- **Heartbeats**: agents call `renew()` on an interval. After
  `renewal_interval_s * max_missed` without a renewal, the lease is stale.
- **Sweeper** (`LeaseManager.sweep()`): expires stale leases, cascades expiry
  down the subagent tree (a child's authority derives from its parent — a
  diligently-renewing child still expires when its parent dies), requeues the
  tasks, writes a `lease_expired` audit event per expiry, and fires
  `on_expire` hooks (observability #23). Observers must not break the sweep;
  hook exceptions are swallowed.
- **Zombie protection**: all effectful writes go through `check_valid()`. A
  stale agent resuming late holds an old epoch; its writes raise
  `LeaseExpiredError`. Epochs are tracked per task even after deletion, so a
  reassigned task always invalidates every previous token.

## Exactly-once effects

Reassignment deliberately keeps the **task id stable**, so the existing
idempotency journal (`orchestrator/idempotency.ExecutionRunner`) sees the
original execution, the reassignment restart, and any zombie completion as
the same (task → execution → step) identity — effects run exactly once by
construction there, not here. See `tests/unit/test_leases.py::test_idempotent_effects_with_execution_runner`.

## Deliberate non-features

- No durable lease state: leases are in-memory. Durability of *effects* is
  the journal's job; after a process restart there are no leases and workers
  re-acquire cleanly. Persisting leases would add a recovery protocol without
  adding guarantees the journal doesn't already provide.
- No automatic background thread: the runtime calls `sweep()` on its own
  schedule so tests can drive time deterministically (injectable `clock`).
