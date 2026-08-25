# MAVR — Multi-Agent Security Vulnerability Research System

> **WARNING: Authorized security testing only.**
> MAVR is a tool for conducting security testing against systems you are
> explicitly authorized to test. It has **no default target**. You must
> configure a scope policy describing exactly which systems and actions are
> permitted before any network activity occurs. Use of this tool against
> systems without authorization is unlawful and unethical.

## What it is

MAVR is a local, multi-agent system that orchestrates AI agents to discover,
validate, and report security vulnerabilities. It is designed to be:

- **Safe by default** — free-only model routing, hard scope enforcement,
  four-agent PoC review, human-in-the-loop for active testing and submission.
- **Local-first** — runs on your laptop, talks to model providers, stores
  evidence and findings in a local SQLite database and filesystem.
- **Auditable** — every state transition is recorded; every claim in a
  final report links to an evidence item.

## Installation

```bash
# Requires Python 3.11+
python3.11 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

After install, the `system` CLI is available:

```bash
system --help
# or
python -m mavr --help
```

## Quick Start

1. **Initialize local state** (config dir, default config, database):
   ```bash
   system init run
   ```
2. **Verify the install**:
   ```bash
   system doctor run
   ```
3. **Start the local server** (API + UI, Phase 7):
   ```bash
   system serve run
   ```
4. **Create and run a campaign** (Phase 2+):
   ```bash
   system campaign new --target example.com
   system campaign list
   ```

## Scope Policy Requirement

Before any campaign runs, you must define a scope policy that explicitly
authorizes:

- The target(s) (URLs, hosts, IPs)
- The actions allowed (read-only enumeration, controlled testing, etc.)
- Whether `active_testing` is permitted
- Whether `explicit_unsafe_networking` (e.g. private-network SSRF) is
  permitted, and only then with a separate `human_approved` flag

MAVR will refuse to run any tool call that is not covered by the active
campaign's scope policy.

## Status

| Phase | Status |
|------:|:-------|
| 1 — Project layout, packaging, CLI skeleton | done |
| 2 — Config, secrets, SQLite, schemas, scope policy | next |
| 3 — Orchestrator, runtime, finding state machine | planned |
| 4 — Providers, router pool, model catalog | planned |
| 5 — Search + safe extraction | planned |
| 6 — Finding review workflow | planned |
| 7 — Local web UI + observability | planned |
| 8 — Hardening + packaging | planned |

## License

Apache-2.0. See `LICENSE`.
