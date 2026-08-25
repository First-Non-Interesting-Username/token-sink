# Configuration Reference

Configuration lives in a single YAML or TOML file (extension selects the
format). Validation is **collect-and-report**: `load_config()` gathers every
problem into one `ConfigError.errors` list so all issues are fixed before any
worker starts (PLAN.md §16). Unknown top-level sections are errors, not
warnings — typos must not be silently ignored.

## Sections

| Section | Keys | Default | Notes |
|---|---|---|---|
| `server` | `host`, `port` | `127.0.0.1`, `8737` | Port validated 1–65535 |
| `storage` | `database_path`, `artifact_path` | `data/tokensink.db`, `data/artifacts` | Must have a filename component |
| `providers` | `credential_refs`, `allowlist` | `{}`, `[]` | Values must be secret *references* (e.g. `op://vault/x/key`), never raw keys — §15 forbids secrets in config |
| `routing` | `free_only`, `router_count` | `true`, `2` | `free_only` defaults ON; routers 1–32 |
| `budgets` | `agent_timeout_seconds`, `max_tokens_per_agent` | `900`, `500000` | Must be positive |
| `review` | `quorum` | `4` | 1–4 (four-agent PoC review panel, §10.5) |
| `retention` | `days` | `90` | Must be positive |
| `redaction` | `enabled` | `true` | Strict bool; redaction on by default per §15 |
| `logging` | `level` | `INFO` | DEBUG/INFO/WARNING/ERROR/CRITICAL |

Safe-by-default principle: anything that reduces safety (free-only off,
redaction off) requires an explicit value; nothing dangerous happens through
omission.
