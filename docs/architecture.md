# MAVR Architecture

> **WARNING: Authorized security testing only.** MAVR runs against
> systems you have explicit, written authorization to test. There is
> no default target.

This document is a high-level tour of the MAVR code base. It maps the
Python packages under `mavr/` to the architectural concepts in the
specification (§4) and the safety guarantees in §9.3 / §19 / §21.

## Bird's-eye view

MAVR is a local-first, single-host, multi-agent system. The user
starts a campaign against a target they have authorized; MAVR
orchestrates LLM-driven agents that search, extract, analyze, prove,
review, and report security findings, then writes everything to a
local SQLite database and a content-addressed artifact directory.

```
                       ┌────────────────────────────────────┐
                       │            human operator          │
                       │      (scope, approvals, submit)    │
                       └─────────────────┬──────────────────┘
                                         │  CLI / UI
                                         ▼
┌─────────────────────────────────────────────────────────────────────┐
│                           mavr.cli / mavr.api / mavr.ui            │
│   Typer CLI   +   FastAPI server   +   static HTML/JS UI            │
└─────────────────┬───────────────────────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────────────────────────┐
│                        mavr.orchestrator                            │
│   • task queue with leases, heartbeats, retries                     │
│   • agent runtime with budgets, redaction, kill-switch              │
│   • audit log + finding state machine                               │
└────┬──────────────┬──────────────┬──────────────┬───────────────────┘
     │              │              │              │
     ▼              ▼              ▼              ▼
┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────────┐
│ policy   │  │ routers  │  │ search   │  │ findings         │
│ engine   │  │  pool    │  │ engine   │  │ (lifecycle,      │
│ (SSRF,   │  │  (free,  │  │ (ddgs,   │  │  reviews,        │
│  scope,  │  │  circuit │  │  extract,│  │  workflow,       │
│  action) │  │  breaker)│  │  safety) │  │  traceability)   │
└──────────┘  └─────┬────┘  └──────────┘  └──────────────────┘
                    │
                    ▼
              ┌──────────┐         ┌──────────────────┐
              │ providers│ ──────▶ │ usage accounting │
              │ (openai  │         │ + cost rollup    │
              │  compat, │         └──────────────────┘
              │  custom, │
              │  gemini, │
              │  hf, …)  │
              └──────────┘
                    │
                    ▼
        ┌─────────────────────────────────────┐
        │   mavr.storage (sqlite + artifacts) │
        │   mavr.observability (structlog,    │
        │   metrics, audit, run-bundle export)│
        └─────────────────────────────────────┘
```

## Package tour

| Package | Role | Spec reference |
|---|---|---|
| `mavr.cli` | Typer-based `system` CLI; subcommands for `init`, `doctor`, `serve`, `campaign`, `provider`, `model`, `finding`, `report`, `approval`, `logs`, `serve`. | §11, §14 |
| `mavr.api` | FastAPI server (`/api/...`) and SSE stream (`/api/events/stream`); JSON schemas for the UI. | §13 |
| `mavr.ui` | Static HTML/JS UI served by the API. | §13 |
| `mavr.orchestrator` | Task queue (`queue.py`), runtime (`runtime.py`), audit (`audit.py`), kill switch (`killswitch.py`), redaction (`redaction.py`), backoff (`backoff.py`), failure classifier (`failures.py`). | §6, §12 |
| `mavr.routers` | Parallel router pool, free-only filter, circuit breakers, dead-letter queue, usage accounting. | §7, §8 |
| `mavr.providers` | LLM provider adapters (OpenAI-compatible, Gemini, HuggingFace, OpenCode Zen, Kilo gateway, custom) plus the model catalog and registry. | §7 |
| `mavr.search` | Search engine (ddgs), safe URL fetcher, evidence store, HTML sanitization. | §5 |
| `mavr.findings` | Finding lifecycle (states, transitions, leases), reviews (insert, fold, quorum, dispute), workflow (discovery → impact → PoC → review → polish → final → tombstone). | §10 |
| `mavr.reports` | Final-report writer and submission (always human-approved). | §10.6, §17 |
| `mavr.policy` | Scope policy engine + SSRF denylist. | §4, §9.3 |
| `mavr.approvals` | Human-approval tokens (active testing, submission, scope change, deletion). | §10, §17 |
| `mavr.secrets` | OS-keyring-backed secret store. | §11 |
| `mavr.storage` | SQLite + migrations + artifact store (UUID-addressed, path-traversal safe). | §4, §11 |
| `mavr.observability` | structlog config, metrics, audit, run-bundle export. | §14 |
| `mavr.schemas` | Pydantic v2 entity definitions. | §4 |
| `mavr.config` | AppConfig loader + defaults. | §11 |
| `mavr.migrations` | Versioned SQL migrations under `mavr/migrations/versions/`. | §4, §11 |

## Data model

The SQLite database has the following top-level tables. Foreign keys
are on everywhere they should be; the schema is created by the
versioned SQL migrations in `mavr/migrations/versions/`.

* `campaigns`, `scope_policies`
* `agents`, `tasks`, `task_dependencies`, `task_attempts`
* `findings`, `finding_versions`, `finding_transitions`, `finding_leases`
* `pocs`, `reviews`, `finding_review_summaries`
* `final_reports`
* `evidence_items`, `extracted_sources`
* `providers`, `models`, `router_decisions`, `usage_events`, `circuit_breakers`, `dead_letter`
* `approvals`, `kill_switch`, `audit_events`, `system_events`
* `quarantine_log`, `schema_migrations`

Artifacts (raw HTTP bodies, extracted HTML, PoC files) live on the
local filesystem under the configured `artifact_dir`. Each file is
named by its UUID — never by user-provided name — and every read
goes through a path-traversal check.

## Concurrency model

MAVR is single-host and single-process by default. The orchestrator
is an in-process coroutine; multiple workers can co-exist in the
same process by passing different `owner=` strings to
`Orchestrator.dispatch`. The task queue uses an atomic
`UPDATE … WHERE status='pending'` for lease acquisition, so adding
more processes is safe: they will race for leases via SQLite's
serialized writer lock. A lease sweeper reaps expired leases.

For a single-process setup, this is the simplest configuration:

```python
orch = Orchestrator(db_factory=db.connect)
await orch.start()
# ... enqueue tasks ...
results = await orch.dispatch(owner="worker-1", agent=agent, handler=handler)
await orch.stop()
```

## Safety boundaries

The following invariants are enforced at multiple layers:

1. **Scope before action.** Every tool call that touches the network
   goes through `mavr.policy.engine.ScopePolicyEngine`. The default
   scope policy is empty: nothing is allowed.
2. **Private-network denylist.** The policy engine and the search
   subsystem share a hard-coded denylist of private, loopback,
   link-local, multicast, CGNAT, and cloud-metadata ranges. The
   denylist is bypassed only when **both**
   `explicit_unsafe_networking=True` **and** `human_approved=True`
   are set on the scope policy.
3. **DNS rebinding defense.** Hosts are resolved at request time and
   the resolved IPs are checked against the denylist before every
   network call.
4. **Free-only routing.** The router pool refuses to dispatch to any
   model whose `free_status` is not `confirmed`. The override
   requires a campaign-level `human_approved` flag.
5. **Kill switch.** The `kill_switch` table is the single source of
   truth across processes. The runtime refuses any handler that
   calls `RuntimeContext.charge_network()` while the switch is
   active, and the API surfaces a banner to the UI.
6. **Prompt-injection containment.** Every piece of fetched content
   is wrapped as `UNTRUSTED_INPUT` before being passed to an LLM.
   The workflow rejects descriptions, PoC commands, and polished
   bodies that contain known injection patterns.
7. **Four-agent PoC review.** Every PoC is reviewed by four
   independent agents (selected through the diversity router). The
   default quorum policy is `all_accept_or_3_of_4_no_blockers`.
8. **Final-review traceability.** A finding only advances to
   `vulnerabilities` when every claim in the polished body either
   links to a real evidence UUID or is explicitly labeled analysis.
9. **Human-in-the-loop for submission.** `mavr.reports.submission.submit`
   requires an unconsumed, campaign-scoped approval token of action
   `submission`. The HTTP transport is opt-in and SSRF-checked.
10. **No silent deletion.** Findings are tombstoned only after both
    the original review and a dispute review have concluded
    `incorrect` (`validity=invalid`, `verdict=reject`).

## Failure handling

* Transient errors (network blips, rate limits) are retried with
  exponential backoff + jitter, up to `task.max_attempts` (default 3).
* Permanent errors (policy violations, model-quality errors) are
  quarantined: the task moves to `quarantined`, the redacted inputs
  land in `quarantine_log`, and an audit event is recorded.
* The lease sweeper reclaims expired leases and dead-letters tasks
  that exceed the configured retry budget.

## Observability

* structlog JSON output to stdout (and optionally to a log file).
* Prometheus-style metrics under `/api/metrics` (counters + gauges).
* The audit log (`audit_events`) is append-only and is the source of
  truth for after-the-fact review.
* The system event log (`system_events`) backs the SSE feed and is
  pruned to the configured ring-buffer size.
* `mavr.observability.bundle.export_run_bundle` produces a redacted
  zip of a campaign for handoff to a remote reviewer.

## Spec coverage

| Spec section | Where it lives |
|---|---|
| §4 Architecture | this document |
| §5 Search + extraction | `mavr.search` |
| §6 Orchestrator | `mavr.orchestrator` |
| §7 Providers | `mavr.providers` |
| §8 Routers | `mavr.routers` |
| §9.3 SSRF / scope | `mavr.policy`, `mavr.search.safety` |
| §10 Findings | `mavr.findings` |
| §11 Config / secrets | `mavr.config`, `mavr.secrets` |
| §12 Retries / leases | `mavr.orchestrator.queue`, `mavr.orchestrator.runtime` |
| §13 API / SSE | `mavr.api`, `mavr.ui` |
| §14 Observability | `mavr.observability` |
| §17 Approvals / submission | `mavr.approvals`, `mavr.reports.submission` |
| §19 Tests | `tests/` |
| §21 Definition of Done | `tests/security/test_acceptance.py` |
