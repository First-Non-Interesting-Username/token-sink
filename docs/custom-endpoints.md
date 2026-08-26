# Custom provider endpoints (PLAN Phase 3, §8.2 — issue #250)

Users can point token-sink at any OpenAI-compatible server via the
`custom_endpoints` config section.

## Config shape

```yaml
providers:
  free_only: false        # gates custom endpoints too (see below)

custom_endpoints:
  - name: my-relay                      # unique; used as `provider test <id>`
    base_url: https://relay.example/v1  # http(s):// required
    models: [model-a, model-b]          # optional declared model list
    cost_class: paid                    # free | paid | unknown (default unknown)
    api_key_env_var: MY_RELAY_KEY       # env-var REFERENCE, never the key itself
    requests_per_min: 30                # optional limits
    concurrency: 2
    timeout_s: 120
```

## Rules

- **Cost classification is user-declared.** The tool cannot verify pricing on
  an arbitrary server, so an undeclared `cost_class` stays `unknown`.
- **Fail closed under `free_only`:** endpoints with `cost_class: unknown` or
  `paid` are rejected at startup when `providers.free_only: true`
  (unknown-status models must never route in free-only mode — see #66).
- **Keys are references.** `api_key_env_var` must look like an env var name,
  must be set at load time, and its value only ever travels in the
  Authorization header — it is never logged or included in error messages.
- Validation errors are aggregated with actionable messages before launch
  (`config.loader.validate_dict`); a broken endpoint entry is not half-loaded.

## `provider test <id>`

```
token-sink provider test my-relay --config config.yaml
```

Probes `GET {base_url}/models`, reports reachability, latency, and the model
list. HTTP failures surface the status code only; transport failures surface
the exception type only. Exit code 0 = healthy.
