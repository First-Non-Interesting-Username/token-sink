# Provider setup

MAVR ships with adapters for several model providers. All of them
are free-only by default; the router pool refuses to dispatch to a
model whose `free_status` is not `confirmed`.

This page covers the supported providers, how to configure their
API keys, and how to add a custom endpoint.

## Built-in providers

| Provider ID | Free tier? | Default base URL | Notes |
|---|---|---|---|
| `mock` | yes (in-process) | n/a | Used by tests; never talks to the network. |
| `gemini` | yes | https://generativelanguage.googleapis.com | Free tier via AI Studio. |
| `opencode_zen` | yes | https://opencode.ai/zen/v1 | OpenCode Zen free models. |
| `huggingface` | yes | https://api-inference.huggingface.co | Free inference; rate limits apply. |
| `kilo_gateway` | mixed | https://api.kilo.ai | Free models are confirmed; paid require approval. |
| `openai_compat` | per-endpoint | per-endpoint | Use for any OpenAI-compatible endpoint. |
| `custom` | per-endpoint | per-endpoint | Single-endpoint custom adapter. |

A provider is enabled in the config:

```yaml
providers:
  free_only: true
  per_provider_overrides:
    gemini:
      enabled: true
      api_key_secret: "GEMINI_API_KEY"
    opencode_zen:
      enabled: true
      api_key_secret: "OPENCODE_ZEN_KEY"
    huggingface:
      enabled: false            # disabled for this campaign
```

`api_key_secret` is the name of a secret in the configured secrets
backend (keyring, env, or file). MAVR never logs the value; the
audit row only records the key name.

## Secret backends

The `secrets` config block selects how API keys are stored:

```yaml
secrets:
  backend: "keyring"             # default
  file_path: ""                  # only used when backend == "file"
```

### Keyring (default)

Uses the OS keyring via the `keyring` Python library. On Linux this
is the Secret Service (gnome-keyring, KWallet). MAVR stores each
secret under the service name `mavr`:

```bash
# Add a key:
secret-tool store --service=mavr --label="Gemini" api_key "$(cat ~/.gemini_key)"
```

Or use the Python CLI:

```bash
python3 -c "import keyring; keyring.set_password('mavr', 'GEMINI_API_KEY', open('/dev/stdin').read().strip())"
```

### Environment variables

```yaml
secrets:
  backend: "env"
```

The key is read as `MAVR_SECRET_<NAME>` (uppercased, non-alphanum
replaced with `_`). Example:

```bash
export MAVR_SECRET_GEMINI_API_KEY="..."
system serve run
```

### File (offline laptop)

```yaml
secrets:
  backend: "file"
  file_path: "~/.local/share/mavr/secrets.json"
```

The file must be `chmod 600`; MAVR will refuse to read it if the
permissions are too open. The JSON shape is `{ "NAME": "value" }`.

## Custom OpenAI-compatible endpoint

The `openai_compat` and `custom` adapters wrap any OpenAI-compatible
chat endpoint. Add a section under `providers.per_provider_overrides`:

```yaml
providers:
  per_provider_overrides:
    openai_compat:
      enabled: true
      api_key_secret: "MY_LOCAL_LLM_KEY"
      base_url: "http://127.0.0.1:11434/v1"
      model_keys:
        - "llama3.1:70b"
```

`model_keys` enumerates the model strings the adapter should
expose. MAVR will only ever talk to models in this list.

If your endpoint is a self-hosted LLM that may resolve to a
private-network address, you also need a scope policy with
`explicit_unsafe_networking: true` and `human_approved: true`, and
a `human_approved` flag on the campaign.

## Verifying the configuration

```bash
system provider list
```

This prints every enabled provider, its health status, and the
last successful health check timestamp.

To test an end-to-end call against a specific model:

```bash
system provider ping --provider gemini --model gemini-2.0-flash
```

A successful ping returns the model name and a token count; a
failure returns a structured error.

## Disabling a provider

Set `enabled: false` in the config or pass `--disable gemini` to
`system campaign new`. Disabled providers are silently skipped;
their models are not proposed by the router pool.

## Model catalog

MAVR maintains a small model catalog in
`mavr/providers/model_catalog/catalog.py`. Each entry includes:

* `provider_id`, `model_key`, `display_name`
* `free`, `free_status` (`confirmed` | `unconfirmed` | `paid`)
* `trust_level` (`native_free` | `gateway` | `community`)
* `categories` (a list of `TaskCategory` values the model is
  suited for)
* `context_limit`
* `last_verified` (when the catalog was last sanity-checked)
* `pricing_input_per_mtok`, `pricing_output_per_mtok` (used for
  usage accounting; `null` for confirmed-free models)

To add a new model, edit the catalog, then run:

```bash
system model refresh
```

This re-validates every catalog entry and updates `last_verified`.

## Rotation and revocation

Rotating an API key:

1. Mint the new key in the provider's console.
2. Replace the entry in the secrets backend.
3. Run `system provider ping` to verify the new key.
4. (Optional) Mint a `submission`-style approval token if the
   rotation needs to be recorded in the audit log.

Revoking a key is the same flow, but with the value set to an
empty string. MAVR will report a `MissingSecret` error for the
provider until a new key is supplied.
