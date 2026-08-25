# Frequently asked questions

### Q: Can I use MAVR against any system?

**No.** MAVR is for authorized security testing only. Before any
network action you must have a written scope policy that names
the targets, the actions, and the rate limits. The default
policy allows nothing. See [scope-policy.md](scope-policy.md).

### Q: Does MAVR use paid models?

**By default, no.** The router pool refuses to dispatch to any
model whose `free_status` is not `confirmed`. The override
requires a campaign-level `human_approved=True` flag, and
that flag is recorded in the audit log.

### Q: Can MAVR send an email / Slack message / ticket without my approval?

**No.** Every external write is gated by a human approval token.
Submission of a final report requires a `submission` token and
the explicit `--human-approved` flag on the CLI. The HTTP
transport is opt-in and is re-checked against the SSRF
denylist at submit time.

### Q: What happens if I `kill -9` MAVR mid-campaign?

The in-memory state is lost; the persistent state (SQLite +
artifacts) is not. On the next start, MAVR re-opens the DB,
re-applies any pending migrations, and the lease sweeper
reclaims any task whose lease was held by the dead worker.
The campaign resumes from where it left off. See
[safety-guarantees.md](safety-guarantees.md) G13.

### Q: Can a target page trick MAVR into doing something dangerous?

The system has several defenses:

* Private / loopback / link-local / multicast / CGNAT /
  cloud-metadata IPs are denied at request time. DNS rebinding
  is mitigated by re-resolving before each request.
* Schemes other than `http` and `https` are rejected.
* HTML is sanitized (dangerous tags, event handlers stripped)
  and wrapped as `UNTRUSTED_INPUT` before being passed to an
  LLM.
* Detected prompt-injection patterns in a finding description,
  PoC command, or polished body are rejected at the door.

The full list is in [threat-model.md](threat-model.md) and
[safety-guarantees.md](safety-guarantees.md).

### Q: How is the four-agent review board diverse?

The diversity router picks one model per provider so a single
provider doesn't dominate. When the catalog has only one
provider with a free model, the pool is smaller; this is
documented in the provider list and visible in the UI.

### Q: How do I know the model I'm talking to is actually free?

The model catalog in `mavr/providers/model_catalog/catalog.py`
lists the `free_status` for every model. The catalog is
curated in-tree and verified out-of-band before each release.
The router pool refuses to dispatch to any model whose
`free_status` is not `confirmed`.

### Q: Can I add a custom model or provider?

Yes. For an OpenAI-compatible endpoint, use the `openai_compat`
or `custom` adapter and add a section to
`providers.per_provider_overrides` in the config. For a
non-OpenAI API, write a new `ProviderAdapter` subclass and
register it with the provider registry. The details are in
[providers.md](providers.md).

### Q: What does the run-bundle contain?

A redacted zip with:

* `manifest.json` — campaign metadata
* `config_snapshot.json` — your config with secrets stripped
* `events.jsonl` — system events, redacted of bearer tokens
* `audit.jsonl` — audit events, redacted of bearer tokens
* `findings.json` — findings, reviews, and final reports
  (no PoC payloads)
* `artifacts_index.json` — pointers to artifact files
* `db_dump.sqlite` — a SQLite snapshot with the `approvals`
  table redacted and bearer tokens blanked
* `redaction_manifest.json` — what was stripped and why

The bundle is safe to hand to a remote reviewer. The default
submission transport is `manifest_only`, which writes the
envelope to disk and does not transmit anywhere.

### Q: How do I rotate an API key?

1. Mint the new key in the provider's console.
2. Replace the entry in the secrets backend (keyring, env var,
   or file).
3. Run `system provider ping` to verify the new key.
4. (Optional) Mint a `submission`-style approval token if the
   rotation needs to be recorded in the audit log.

### Q: Can I run MAVR on a laptop with no internet?

Yes, with limitations. You need at least one provider whose
endpoint is reachable (for a self-hosted LLM, the endpoint
must be on the same network or the same machine). Use the
`openai_compat` adapter and the offline configuration. The
PyInstaller single-file binary is documented in
[installation.md](installation.md).

### Q: Does MAVR phone home?

**No.** MAVR does not transmit telemetry, usage data, or
errors to any third party. The only outbound network calls
are to the providers you have explicitly enabled, against the
targets in your scope policy, at the rate limit you have set.

### Q: How do I report a bug or a safety issue?

Open a GitHub issue or, for sensitive disclosures, email the
address listed in the project README. Include the version
(`system --version`), the config file, and a redacted
`system report bundle` for the affected campaign.

### Q: Where is the audit log?

It's a SQLite table (`audit_events`) and a JSONL file (the
`audit.jsonl` entry of the run bundle). Every state
transition, every policy decision, every approval, and every
submission is recorded with the actor id, the prior state, the
new state, and a reason. The audit log is append-only; there
is no API to delete rows.

### Q: How do I tell my auditor what MAVR did?

Run `system report bundle --campaign <CID> --output ./out/`
and hand them the zip. The `redaction_manifest.json` is the
key to understanding what was stripped and why; the rest of
the bundle is human-readable.
