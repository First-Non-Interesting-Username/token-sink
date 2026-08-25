# Configuration reference

MAVR reads its configuration from a YAML file at:

* `$MAVR_CONFIG` if set, else
* `$XDG_CONFIG_HOME/mavr/config.yaml`, else
* `~/.config/mavr/config.yaml` on Linux.

`system init run` writes a default config to that location. Most
keys are optional; the defaults are conservative (free-only,
no scope, no active testing, no private networking).

The schema is `mavr.config.loader.AppConfig`; here is the canonical
shape:

```yaml
server:
  host: "127.0.0.1"
  port: 8421
  log_level: "info"           # debug | info | warning | error
  workers: 1
  sse:
    poll_interval_seconds: 1.0
    ring_buffer_size: 5000

storage:
  db_path: "~/.local/share/mavr/mavr.db"
  artifact_dir: "~/.local/share/mavr/artifacts"
  backup_dir: "~/.local/share/mavr/backups"

routers:
  policy: "best_score_within_budget"   # or consensus | fastest_eligible | diversity
  free_only: true
  allow_paid_override: false
  router_timeout_seconds: 3.0
  default_routers: 3                  # overridden by RouterPool(...) in tests
  quorum_policy: "all_accept_or_3_of_4_no_blockers"

providers:
  free_only: true
  per_provider_overrides:
    gemini:
      enabled: true
      api_key_secret: "GEMINI_API_KEY"
    openai:
      enabled: false                # disabled by default (paid)

orchestrator:
  lease:
    ttl_seconds: 60
    heartbeat_interval_seconds: 15.0
    sweeper_interval_seconds: 10.0
    dead_letter_after_attempts: 5
  runtime:
    backoff_initial_seconds: 1.0
    backoff_max_seconds: 60.0
    backoff_multiplier: 2.0
    backoff_jitter: 0.25
    reclassify_transient_after: 3
  budgets:
    default:
      max_tokens: 200000
      max_time_seconds: 1800
      max_tool_calls: 200
      max_network_requests: 500

search:
  timeout_seconds: 20
  max_redirects: 5
  max_bytes: 5_000_000
  user_agent: "mavr/0.1 (+https://github.com/your-org/mavr)"

logging:
  format: "json"                     # json | console
  file: ""                           # empty -> stdout only
  level: "info"

secrets:
  backend: "keyring"                 # keyring (OS-native) | env | file
  file_path: ""                      # only used when backend == "file"

kill_switch:
  initial_state: "inactive"
```

## Per-section notes

### `server`

The FastAPI server is bound to `127.0.0.1` by default. Change
`host` to expose it on a different interface, but be aware that the
UI/API has no built-in authentication and is intended to be reached
only over loopback or a trusted tunnel.

### `storage`

The artifact directory is created on demand and must be writable
by the MAVR process. Each artifact is a file under
`<artifact_dir>/<uuid>`; the filename is always a lowercase UUIDv4.
Backups are written to `backup_dir` by `system report bundle`.

### `routers`

* `policy` selects the merge policy used by the router pool.
  `best_score_within_budget` is the default; `diversity` is used
  internally for the four-agent PoC review board.
* `free_only` is the global default. A model whose `free_status` is
  not `confirmed` is rejected unless the campaign has
  `human_approved=True`.
* `quorum_policy` controls how PoC reviews are folded.

### `providers`

The provider block lists every provider MAVR is allowed to talk
to. Each entry has an `enabled` flag and an optional
`api_key_secret` (the name of an entry in the OS keyring, an env
var, or a keyfile — see `secrets.backend`).

Disabled providers are silently skipped; their models are not
proposed by the router pool. This is the right knob to flip when
you want to lock MAVR down to a single free provider.

### `orchestrator`

* `lease.ttl_seconds` is how long a leased task is reserved for
  a worker before the sweeper reclaims it.
* `runtime.backoff_*` control the exponential backoff between
  retries of a transient failure.
* `budgets.default` is the per-agent default. The orchestrator
  refuses to spawn an agent with a budget that exceeds the campaign
  budget; the campaign budget is set at campaign creation time.

### `search`

Network knobs for the search and extraction subsystem. The SSRF
denylist is hard-coded; it cannot be disabled by configuration.

### `logging`

* `format: json` is the default and what production deployments
  should use; logs include the campaign id, agent id, task id, and
  finding id when available.
* `format: console` is a pretty-printed alternative for local
  development.

### `secrets`

The default backend is the OS keyring. On Linux this is the
Secret Service (gnome-keyring, KWallet, KeePassXC). MAVR never
logs the values it reads from the keyring. The `env` backend is
useful for CI; the `file` backend is for offline laptops.

### `kill_switch`

`initial_state` is the state on startup. The CLI/API can flip the
switch at any time; the change is persisted in the `kill_switch`
table and the audit log records the actor who flipped it.

## Reloading

The config file is read at process start. To apply changes, restart
the server (`system serve run` again) or, for the CLI, run the
subcommand you want afresh.

## Environment variables

The following environment variables override the config file:

* `MAVR_CONFIG` — path to a different config file
* `MAVR_DATA_DIR` — override the data directory
* `MAVR_DB_PATH` — override the SQLite path
* `MAVR_ARTIFACT_DIR` — override the artifact directory
* `MAVR_LOG_LEVEL` — override the log level
* `MAVR_NO_TELEMETRY=1` — disable optional telemetry
* `MAVR_OFFLINE=1` — refuse to make any network call (useful for
  the PyInstaller offline binary)
