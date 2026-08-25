# token-sink

Multi-agent security vulnerability research orchestrator — see [PLAN.md](PLAN.md)
for the full product/architecture plan this repository is being built from.

**Status:** Phase 1 bootstrap. The module layout below exists; most subsystems
are still empty packages awaiting their issues.

## What it will do

Launch a locally hosted web UI that coordinates multiple AI agents to discover,
validate, document, and report security vulnerabilities for **authorized**
programs only (scope-before-action, evidence-over-assertions, human control —
see PLAN.md §2).

## Repository layout

| Path | Responsibility |
|---|---|
| `cli/` | Command-line entry points (`token-sink init/doctor/serve`, campaign commands) |
| `api/` | Local HTTP API backing the web UI |
| `ui/` | Locally hosted web UI: agents, queues, findings, approvals |
| `orchestrator/` | Campaigns, tasks, leases, retries, lifecycle transitions |
| `routers/` | Independent parallel router workers selecting endpoints/models |
| `agents/` | Agent runtime (`roles/`, `subagents/`, `prompts/`) |
| `providers/` | Provider adapters, endpoint registry, model catalog |
| `search/` | Web search + page extraction with caching and SSRF guards |
| `policy/` | Scope enforcement and tool-call gating |
| `findings/` | Versioned finding records + immutable evidence store |
| `storage/` | Transactional DB + artifact store, migrations, crash recovery |
| `observability/` | Structured events, metrics, audit log |
| `schemas/` | Versioned machine-readable record schemas |
| `config_loader.py` | YAML/TOML config loading + collect-all-errors validation (§16) |
| `config/example.yaml` | Documented example configuration |
| `tests/` | Test suite |

## Configuration

Copy `config/example.yaml`, adjust paths, and validate:

```bash
python -c "from config_loader import load; load('config/example.yaml'); print('OK')"
```

Validation collects **all** problems and reports them together before anything
launches. Credentials are referenced by name (env var / secret path) — never
inline secret values.

## Development

```bash
uv pip install -e '.[dev]'   # or: pip install -e '.[dev]'
pytest
```
