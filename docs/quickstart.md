# Quickstart

> **Authorized security testing only.** MAVR runs against systems
> you have explicit, written authorization to test.

This page walks you through your first end-to-end MAVR run: from
install to a finished report bundle. Estimated time: ten minutes.

## 1. Install

See [installation.md](installation.md). TL;DR:

```bash
python3 -m pip install --user pipx
python3 -m pipx ensurepath
pipx install mavr
```

## 2. Initialize

```bash
system init run
```

This creates the data directory and applies the migrations. On a
typical Linux box the database lives at
`~/.local/share/mavr/mavr.db` and the artifact directory is
`~/.local/share/mavr/artifacts/`.

## 3. Verify the install

```bash
system doctor run
```

You should see every check pass. If a check fails, see the
[troubleshooting](troubleshooting.md) page.

## 4. Start the local server (optional)

The CLI works without the server, but the UI is convenient:

```bash
system serve run
```

The server listens on `http://127.0.0.1:8421` by default. Open it
in your browser to see the dashboard.

## 5. Write a scope policy

A scope policy is a YAML or JSON document that names the targets,
methods, action classes, and rate limits you are authorizing. Save
it as `scope.yaml`:

```yaml
campaign: "demo"
target:
  hosts:
    - staging.example.com
  methods: [GET, HEAD]
  action_allowlist: [read, enumeration]
  rate_limit_per_minute: 30
human_approved: false        # set true ONLY for active testing
explicit_unsafe_networking: false
```

The defaults are intentionally empty: nothing is allowed. Always
review and edit the policy before running anything.

## 6. Create a campaign

```bash
system campaign new --scope-file scope.yaml --name "demo"
```

The CLI prints a campaign id. Save it; you'll need it for the next
step.

## 7. Mint a human-approval token (active testing only)

If your scope policy permits `active_testing`, you also need a
human-approval token before the agents can fire active tests:

```bash
system approval mint --campaign-id <CID> --action active_testing
```

The token is valid for the duration of the campaign and is consumed
the first time it's used.

## 8. Run the campaign

For an offline dry-run against a local mock target:

```bash
system campaign run --campaign-id <CID> --dry-run
```

For a real run:

```bash
system campaign run --campaign-id <CID>
```

The orchestrator enqueues tasks, the router pool picks models, the
agents execute the search → extract → impact → PoC → review pipeline,
and every state transition is recorded in the audit log.

## 9. Inspect the dashboard

Open the UI and navigate to the campaign page. You should see:

* the queue depth over time
* per-model usage and cost
* the audit log
* the list of findings and their state machine progress

## 10. Export a run bundle

When the campaign is done, produce a redacted zip for your records
or for handoff to a remote reviewer:

```bash
system report bundle --campaign-id <CID> --output ./out/
```

The bundle includes `manifest.json`, `findings.json`, `audit.jsonl`,
`events.jsonl`, `usage.json`, a redacted `db_dump.sqlite`, and a
`redaction_manifest.json` that documents what was stripped and why.

## 11. Submit (only when authorized)

Submission is **never** automatic. You must explicitly mint a
submission token and run:

```bash
system approval mint --campaign-id <CID> --action submission
system report submit --campaign-id <CID> --token <TOKEN>
```

The default transport is `manifest_only` (writes the submission
envelope to disk; nothing leaves the host). If you pass
`--transport http --target https://example.com/...` MAVR will
POST a signed envelope, but only after a separate
`--human-approved` flag and an SSRF check on the target host.

## What's next

* Read the [configuration reference](configuration.md) to tune the
  router, the providers, and the rate limits.
* Read the [scope policy authoring guide](scope-policy.md) to learn
  the supported target syntax, the per-action safety knobs, and the
  dispute review flow.
* Read the [threat model](threat-model.md) to understand the
  adversary we are defending against and the limits of those
  defenses.
