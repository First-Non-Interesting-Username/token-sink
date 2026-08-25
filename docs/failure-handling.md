# Failure Handling Matrix (PLAN §18)

Every failure in the system maps to a `FailureClass` (`orchestrator/failures.py`)
which determines the recovery path. Retries are allowed **only** for the
transient classes listed below — everything else has a terminal path.

## Classes and recovery paths

| Failure class | Recovery path | Retry? |
|---|---|---|
| `PROVIDER_OUTAGE` | retry w/ exponential backoff, then failover to another provider | yes (3 attempts) |
| `PROVIDER_RATE_LIMIT` | honor backoff/cooldown headers; longer backoff, lower cap so we never add thundering-herd pressure | yes (4 attempts) |
| `AGENT_TIMEOUT` | one retry with reduced scope, then human intervention | yes (2 attempts) |
| `DATABASE_TRANSIENT` (lock/busy) | short retry, then halt campaign cleanly | yes (3 attempts) |
| `UI_DISCONNECT` | client reconnects; event stream replay by last-event-ID recovers state | yes (reconnects) |
| `QUOTA_EXHAUSTED` | wait for window reset / route to another model; never retry immediately | no |
| `UNKNOWN_MODEL_STATUS` | exclude model from free-only routing until confirmed (§21 hard rule) | no |
| `ROUTER_DISAGREEMENT` | escalate to coordinator consensus path (§7 merge modes) | no |
| `MALFORMED_MODEL_OUTPUT` | dead-letter queue; preserve redacted input/output for diagnosis | no |
| `SEARCH_EXTRACTION_FAILURE` | dead-letter queue after cache/provenance record | no |
| `SCOPE_POLICY_REJECTION` | blocked event + actionable explanation; **never** retried or bypassed | no |
| `DB_INTEGRITY` (interrupt/crash) | crash-recovery path from storage layer (atomic transitions, idempotent tasks) | no |
| `CONFLICTING_EDITS` | versioned finding records resolve; append-only history keeps both | no |
| `POC_SAFETY_FAILURE` | quarantine + human approval gate; hard stop of PoC execution | no |
| `STALE_LEASE` | lease manager reassigns work safely (never double-execute) | no |

## Rules

1. **Retries only for classified transient failures.** Unknown exception types
   classify conservatively as non-transient rather than burning retries.
2. **Preserve failed inputs AND outputs** in a `FailureRecord`, with secrets
   and sensitive data redacted *before* attachment (redaction pipeline is its
   own subsystem). Records go to durable storage verbatim.
3. Every failed attempt emits a `FailureRecord` via an `on_failure` hook, so
   observability (#23) can audit failures even when retries eventually succeed.
4. When retries exhaust on a transient class, the item goes to the dead-letter
   queue or a documented human path — it is never dropped silently.

## Implementation notes

- `classify(exc)` maps exceptions to classes using type-name heuristics so
  subsystems don't need a dependency on this module.
- `with_retry(fn, cls)` implements the policy loop; inject `sleep` in tests.
- The in-memory `DeadLetterQueue` here is the interface; the storage layer
  (#7) provides the durable backing.

Related: PLAN §7 (router cooldowns/circuit breakers), §12 (atomic
transitions), §18 (this matrix), issue #25.

## Retry budgets and classification decisions (issue #91)

- `RetryBudget` enforces per-task **and** per-campaign retry caps. Every retry
  attempt consumes both; when either is exhausted the item goes to the
  dead-letter path. Budgets are counters here — durable backing belongs to
  the storage layer (#7).
- `classify(exc, rules=...)` accepts data-driven rules from provider adapters
  (§8.1): `(pattern, FailureClass)` pairs matched against type name + message
  before the built-in heuristics. Unknown errors still default to
  non-transient — no blind retries.
- `MODEL_QUALITY` (raise `ModelQualityError` for schema-valid-but-wrong
  output) never retries on the same model; its recovery path feeds a negative
  signal to the score system (#17) and allows rerouting to another model.
- Backoff delays now carry jitter (uniform factor in [0.5, 1.0)) so concurrent
  retriers do not synchronize; inject `rng=` in tests for determinism.
- `FailureLogger` records every classification and retry decision with its
  reason for the audit trail (§14/§15).
