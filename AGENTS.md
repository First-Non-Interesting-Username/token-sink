# AGENTS.md

## What is MAVR?

MAVR (Multi-Agent Security Vulnerability Research System) is a local,
authorized security-testing platform that orchestrates multiple AI agents to
discover, validate, and report security vulnerabilities — **only** against
targets for which the user has explicit, written authorization.

## Safety Rules (non-negotiable)

1. **Scope before action.** No tool call runs against a network target without
   an active scope policy attached to a campaign. The scope policy is the
   single source of truth for what is and is not allowed.
2. **Free-only by default.** The router refuses to send tasks to a model
   whose free/paid status is unknown or paid. Paid routing is opt-in per
   campaign and requires a `human_approved` flag.
3. **Human approval for active testing and submission.** Active exploitation
   against a live target and submission of any external report require an
   explicit, session-scoped human approval token. There are no automatic
   submissions.
4. **Four-agent PoC review.** Every proof-of-concept is reviewed by four
   independent agents (diverse providers/models via the router diversity
   mode). Quorum policy decides advancement; blocking safety/validity issues
   always override quorum.
5. **Evidence-traceability.** Every factual claim in a final report must
   reference an `EvidenceItem` UUID, or be explicitly labeled as analysis.
6. **No silent deletion.** Findings are only tombstoned after both the
   original review AND an independent dispute review conclude the finding is
   incorrect. The audit record is preserved forever.

## Architecture (spec §4)

```
mavr/
  cli/          # Typer-based `system` CLI
  api/          # FastAPI local API (wired in Phase 7)
  ui/           # Local web UI (Phase 7)
  orchestrator/ # Task queue, leases, agent runtime
  routers/      # Parallel model router pool
  agents/       # Agent roles, subagents, prompts
    roles/
    subagents/
    prompts/
  providers/    # LLM provider adapters, registry, model catalog
    adapters/
    registry/
    model_catalog/
  search/       # ddgs search + safe extraction
  policy/       # Scope policy engine
  findings/     # Finding state machine
  storage/      # aiosqlite + artifact filesystem
  observability/# structlog + metrics
  schemas/      # Pydantic v2 schemas
tests/
docs/
examples/
migrations/     # versioned SQL
config/         # default config
scripts/        # install / dev scripts
```

## Build Phases

| Phase | Scope |
|------:|-------|
| 1 | Project layout, packaging, CLI skeleton (this bead) |
| 2 | Config, secrets, SQLite storage, schemas, scope policy, agent UUIDs |
| 3 | Orchestrator, task queue, leases, retries, finding state machine, audit |
| 4 | Provider interface, free adapters, router pool, model catalog |
| 5 | Search (ddgs) + safe extraction + evidence store |
| 6 | Finding review workflow: discovery → impact → PoC → 4-agent review → polish → final |
| 7 | Local web UI + observability (FastAPI + SSE) |
| 8 | Hardening, security tests, recovery tests, load tests, docs, packaging |

## Working With This Repository

- **Python:** 3.11+
- **Install (dev):** `pip install -e ".[dev]"`
- **CLI:** `system --help` or `python -m mavr --help`
- **Lint:** `ruff check .`
- **Type check:** `mypy mavr`
- **Test:** `pytest`

## Threat Model (summary)

- Adversarial web content must not override system policy. Extracted content
  is labeled `UNTRUSTED_INPUT` in prompts.
- SSRF is blocked at the policy + DNS-resolution layers.
- Secrets are stored in the OS keyring and never logged.
- The kill switch halts new network actions and surfaces a banner.

See `docs/` (added in later phases) for the full threat model and safety
guarantees.
