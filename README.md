# token-sink

A Linux-only CLI application that launches a locally hosted web UI for
coordinating multiple AI agents that discover, validate, document, and report
security vulnerabilities — research only against explicitly authorized,
in-scope targets.

See [PLAN.md](PLAN.md) for the full implementation plan (product behavior,
architecture, safety controls, acceptance criteria). It is the source of truth
for what we are building.

## Status

Phase 1 (Foundation) in progress:

- ✅ Package skeleton (`src/tokensink/`) with module boundaries per PLAN.md §4
- ✅ Configuration loading (YAML/TOML) with collect-and-report validation (§16)
- ⬜ Database and schemas
- ⬜ Campaign and scope policy
- ⬜ Agent UUIDs, basic CLI and local API

## Development

```bash
uv venv && . .venv/bin/activate
uv pip install -e '.[dev]'
pytest tests/
```

## Safety

This project builds security-research tooling. Its own rules apply to how it
is developed: never weaken scope checks or approval gates; never commit real
credentials. See [AGENTS.md](AGENTS.md).
