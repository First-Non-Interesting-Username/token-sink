# Architecture Overview

Status: **planning-stage documentation.** The repo currently contains package
stubs, schemas-to-be, and tests infrastructure; the behavior described here is
the design of record from [PLAN.md](../PLAN.md). Where a component is not yet
implemented this doc describes what will land and why it is shaped that way.
Update this document as components land (see AGENTS.md documentation rules).

## What the system is

A Linux-only CLI application that launches a locally hosted web UI
coordinating multiple AI agents to discover, validate, document, and report
security vulnerabilities for authorized programs (Hack Club Security).
Design principles: scope before action, parallelism by default, evidence over
assertions, redundancy for important decisions, human control, provider
independence (PLAN §2).

## Component map

```text
                ┌──────────────────────────────┐
   operator ───▶│  CLI (cli/)  │  Web UI (ui/) │
                └───────┬──────────────┬───────┘
                        │              │ events / REST
                        ▼              ▼
                ┌──────────────────────────────┐
                │     Local API layer (api/)   │
                └───────┬──────────────────────┘
                        ▼
                ┌──────────────────────────────┐
                │      Orchestrator            │  campaigns, tasks,
                │      (orchestrator/)         │  leases, retries, UUIDs
                └──┬─────────┬─────────┬───────┘
                   ▼         ▼         ▼
          ┌────────────┐ ┌──────────┐ ┌───────────────────┐
          │ Router pool│ │ Agent    │ │ Search/extraction │
          │ (routers/) │ │ runtime  │ │ (search/)         │
          └─────┬──────┘ │ (agents/ │ └─────────┬─────────┘
                │        │ )        │           │
                ▼        └────┬─────┘           ▼
   ┌──────────────────────┐   │      ddgs / curl / jina.ai
   │ Provider adapters +  │◀──┘        (SSRF-guarded)
   │ model catalog        │
   │ (providers/)         │
   └──────────────────────┘

   Cross-cutting: policy/safety (policy/), finding lifecycle (findings/),
   storage (storage/), observability & audit (observability/),
   versioned schemas (schemas/)
```

### CLI and web UI (PLAN §3.1.1–2, §13, §17)

The CLI (`cli/`) creates campaigns, starts/stops the local server and worker
runtime, and exposes non-interactive commands for automation. The locally
hosted UI (`ui/`) shows live agent activity, findings by lifecycle stage,
usage/costs, provider health, approvals, and logs. Every state-changing UI
action maps to an auditable API call with a CLI equivalent where practical.

### Orchestrator (PLAN §3.1.3)

Maintains campaigns, tasks, dependencies, retries, leases, and locks. Assigns
a globally unique UUID to every agent/subagent and records all activity.

### Router pool (routers/, PLAN §7)

Multiple independent router workers evaluate pending tasks concurrently — one
slow or failed router must never block others. Each router returns a
structured candidate plan (rationale, confidence, expected cost, fallbacks);
a coordinator merges candidates via configurable policies: consensus
(high-risk), fastest-eligible (latency-sensitive), best-score-in-budget
(ordinary), diversity (independent reviews — avoid routing all work to one
model family). Safeguards: no paid models in free-only mode, skip
over-quota/unhealthy providers, circuit breakers + backoff + cooldowns,
dead-letter queue. Decisions are reproducible from recorded inputs and model
catalogs (decision log, issue #55).

### Providers (providers/, PLAN §8)

All AI providers normalize behind one adapter interface (capabilities, context
limits, pricing/free status, rate limits, streaming, tool calling, structured
output, health, usage extraction, error normalization). Three classes:
native free providers; partly-free gateways (OpenCode Zen, Kilo Gateway) that
require strict free-model allowlists — unknown free-status models are excluded
from free-only routing; custom user endpoints (OpenAI-compatible). A dynamic
per-model/per-category score system (§8.3) plus a versioned benchmark suite
(§8.4) inform routing but never replace live measurements.

### Agent runtime (agents/, PLAN §6)

Every agent/subagent carries UUID, parent UUID, campaign, role/task,
status (`created → queued → assigned → running → waiting → completed`, with
`failed/cancelled/blocked` exits), model assignment, and budget. Runtime
supports heartbeats, stale detection, expiring leases, budget enforcement,
cancellation propagation to subagents, structured-output validation, and
retry policies distinguishing transient / permanent / policy /
model-quality failures. Parents summarize and cite subagent outputs rather
than treating them as unquestioned truth.

### Search & extraction (search/, PLAN §9)

`ddgs` search with caching/dedup; extraction via `curl` with an optional
unauthenticated jina.ai fallback. Timeouts, size limits, content-type checks,
redirect policy, SSRF protections (no local/private/link-local/metadata
addresses unless explicitly authorized). Extracted content is labeled
untrusted input; raw content hashes + source URLs preserved for provenance;
epistemic labeling distinguishes source fact / inference / unverified claim /
needs active confirmation.

### Finding lifecycle (findings/, PLAN §10)

A state machine with versioned records and append-only transition history:

```text
initial_findings → review_cycle_1 → validated_or_disputed → impact_analysis
  → poc_draft → poc_review → polished_report → final_review → vulnerabilities
```

Key gates: first review cycle with dispute path (deletion only on two
independent "incorrect" conclusions, tombstone + audit record); four-agent PoC
review with independent-first or discussion-first modes and quorum rules;
polishing that may not change technical facts; final review against source
evidence; submission as a separate human-approved action.

### Policy & safety layer (policy/, PLAN §5, §15)

Evaluates every tool call against the campaign before execution: target scope,
allowed tools/methods, rate limits, approval requirements. Failed checks
produce blocked events with actionable explanations — enforcement lives here,
not in prompts. Includes kill switch, approval gates, and SSRF/path-traversal/
command-injection defenses.

### Storage (storage/, PLAN §12)

Local-first: transactional DB for metadata, files for evidence/artifacts.
Atomic transitions, idempotent task execution, unique UUID/event IDs, crash
recovery, resumable campaigns, backup/export/import, artifact checksums,
retention + secure deletion, migration versioning. Content hashes, never
filenames alone, are identity; artifact names are traversal-proof.

### Observability (observability/, PLAN §14)

Structured events and metrics (agent, model/provider, research, system)
queryable by campaign and time range; tamper-evident audit log for approvals,
blocked actions, state changes, submissions. Privacy-preserving telemetry by
default — no target data to external analytics without explicit consent.

## How the pieces fit together (request flow)

1. Operator defines a campaign with explicit scope, authorization reference,
   budgets, and policy (§5) via CLI/UI.
2. Tasks enter the orchestrator's queue; the router pool selects
   endpoint/model candidates per task using scores, load, quotas, budgets,
   and sensitivity/trust constraints; the coordinator merges plans.
3. The agent runtime executes the task under tool permissions, scope policy,
   timeouts, budgets, and output-schema validation; usage accounting
   attributes tokens/costs to provider/model/agent/task.
4. Discovered issues become findings that traverse the gated lifecycle; every
   claim keeps evidence provenance; reviews produce recorded opinions and
   dissent.
5. All along, observability emits events/metrics and tamper-evident audit
   entries; the UI streams them with last-event-ID reconnect recovery.

## Related docs

- [Operator guide](operator-guide.md) — install, configure, run safely.
- [Safety & scope authoring](safety-and-scope.md) — writing campaign scopes
  and understanding what the policy engine blocks.
- [Contributor guide](contributor-guide.md) — repo layout, conventions,
  how to add providers/tests/docs.
