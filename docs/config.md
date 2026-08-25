# Configuration reference (PLAN.md §16)

The primary config format is YAML (TOML also accepted, detected by file
extension). Validation is **collect-and-report**: at startup every invalid
field across all sections is reported in one error listing — the process
never fails on the first bad key.

Example:

```yaml
server:
  host: 127.0.0.1   # local-only binding by default
  port: 8080

storage:
  db_path: /var/lib/token-sink/tokensink.db
  artifact_dir: /var/lib/token-sink/artifacts

providers:
  # References only — never literal secrets (§15).
  credentials:
    openai: env:OPENAI_API_KEY
    anthropic: keyring:anthropic-main
  allowlist: []          # provider ids; empty = all allowed
  model_allowlist: []    # model ids; empty = all allowed

free_only: false

router:
  count: 2           # parallel router workers
  concurrency: 4     # tasks evaluated per worker

agents:
  token_budget: 1000000    # per-agent budget; null/omitted = unlimited
  request_budget: null
  timeout_seconds: 600

search:
  max_results: 20
  extraction_timeout_seconds: 30
  extraction_max_bytes: 5000000

campaign_defaults: {}      # free-form defaults merged into new campaigns

active_testing_enabled: false   # global gate for active testing

review:
  quorum: 4        # four-agent PoC review quorum (§10.5)

retention:
  days: 365
  redaction_enabled: true

logging:
  level: INFO      # DEBUG | INFO | WARNING | ERROR
  file: /var/log/token-sink.log    # or omit for stderr

telemetry:
  external: false  # privacy-preserving default; no external analytics (§14)
```

## Credential references

`providers.credentials` values are **references**, never secret material:

- `env:<VAR>` — read from an environment variable at startup
- `keyring:<id>` — resolved from the OS credential store

A config value that looks like a literal secret (`sk-…`, `ghp_…`, JWTs,
`password: …` shapes) fails validation so live keys can't be committed to git.
`system doctor` (future) will verify that referenced env vars resolve.
