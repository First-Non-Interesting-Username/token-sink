# Configuration (PLAN §16)

The config file is YAML (see `examples/config.example.yaml` for a fully
documented example). Loading and validation live in
`config/loader.py`.

## Behavior

- **Collect-all-errors validation.** `load_config_collect(path)` returns
  `(Config, errors)`; `load_config(path)` raises `ConfigError` listing every
  problem. Workers must never launch while `errors` is non-empty.
- **Key-pointing messages.** Each error names the offending key path, e.g.
  `server.port: must be an integer >= 1, got 0`.
- **Unknown sections are errors.** Typos (`servor:`) surface immediately
  instead of silently falling back to defaults.
- **Credentials are references.** `providers.credentials` maps provider name
  → environment variable NAME. Literal secret values fail validation, and a
  referenced env var that isn't set is an error (fail closed).

## Sections

server, storage, providers (allowlists, free_only, credentials), router,
agents (budgets/timeouts/heartbeat), search, campaign_defaults,
scope_policy, review, retention, logging. See the example config for every
key with defaults.

## Defaults

Every section is optional; dataclass defaults in `config.py` define them.
Notable safety-leaning defaults: `free_only: true`,
`scope_policy.active_testing_allowed: false`, `telemetry_enabled: false`.
