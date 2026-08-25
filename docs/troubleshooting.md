# Troubleshooting

This page lists the most common MAVR errors and what to do about
them. Errors are grouped by component.

## Install and Python environment

### `system: command not found`

The user-site `bin` is not on your `$PATH`. Add it:

```bash
# bash
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc

# zsh
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.zshrc
source ~/.zshrc
```

If you used `pipx`, the path is the same; `python3 -m pipx ensurepath`
adds it for you.

### `externally-managed-environment` (PEP 668)

The system Python refuses user-site installs. Use one of:

```bash
pipx install mavr              # recommended
python3 -m venv .venv && \
  source .venv/bin/activate && \
  pip install mavr             # dev workflow
```

### `ImportError: cannot import name 'X' from 'mavr.Y'`

A stale MAVR install is shadowing the one you want. Inspect
`sys.path`:

```bash
python3 -c "import sys; print('\n'.join(sys.path))"
```

The first entry should be the venv / pipx site-packages, not a
working tree you forgot about. Reinstall:

```bash
pipx reinstall mavr            # or
pip install --force-reinstall --user mavr
```

## Database and migrations

### `sqlite3.OperationalError: no such table: schema_migrations`

The database file was created against an older schema or was
hand-edited. Run:

```bash
system init run
```

This applies any pending migrations and is idempotent.

### `RuntimeError: migration 0001 has a checksum mismatch`

A migration SQL file was modified after it was applied. This is
intentionally a hard error — silent drift between the on-disk
schema and the SQL file can corrupt the system. Revert the SQL
file change, or restore the database from a backup.

### `sqlite3.DatabaseError: database disk image is malformed`

The DB file is corrupted. Stop MAVR, restore from the most recent
backup, and run `system init run` to verify. If no backup exists,
recreate the database and re-import any run bundles you have.

## Scope and policy

### `ssrf_denylist: target X is in a denied network range`

The host resolves to a private, loopback, link-local, multicast,
CGNAT, or cloud-metadata IP. This is the expected behavior. To
override, the scope policy must set both
`explicit_unsafe_networking: true` and `human_approved: true`,
and the campaign must be created with `--human-approved`.

### `forbidden_action_class: action class 'denial_of_service' is always prohibited`

There is no way to override this. Refactor the workflow to avoid
the action class.

### `host_not_in_scope: host 'X' not in scope.allowed_targets`

Add the host to `scope.allowed_targets` (with the right syntax
— see [scope-policy.md](scope-policy.md)) and re-run. The change
takes effect immediately; the engine re-reads the policy on every
call.

## Kill switch

### "KILL SWITCH ACTIVE" banner in the UI

Someone (or a watchdog) flipped the kill switch. The CLI/API
refuse to start any new network-bound task while it is active.

To check the state and the reason:

```bash
system kill-switch status
```

To deactivate:

```bash
system kill-switch deactivate --by <operator>
```

The deactivation is recorded in the audit log with the operator
name and a timestamp.

## Provider and router

### `no eligible candidates` on every task

The router pool found no free model. Either:

* the model catalog is empty (run `system model refresh`),
* every enabled provider is in a `paid` state and the campaign
  does not have `human_approved=True`, or
* the circuit breaker is open for every provider.

Check `system provider list` and `system provider breakers`.

### `circuit_open: circuit open for X/Y`

The router has tripped the circuit breaker for a provider/model
after too many consecutive failures. The breaker has a cool-down
period (default 5 minutes) after which the provider is tried
again. To force a reset:

```bash
system provider breakers reset --provider X --model Y
```

### `KeyError: 'MY_SECRET'` from the keyring

The secret backend does not have a value for the named key. Check
the spelling and the configured backend. For the `keyring`
backend, list your stored secrets with:

```bash
secret-tool search service mavr
```

## Tasks and orchestrator

### `QueueError: could not re-lease after transient failure`

A worker tried to renew a lease that the sweeper had already
reclaimed. This is normal under heavy contention; the next
dequeue will pick the task up. If you see it persistently, the
lease TTL is too short for the workload — increase it in the
config.

### `task_attempt outcome = "transient"` repeatedly

A task is failing with a transient classification. Check
`system logs` for the underlying error. If the failure is
permanent (e.g. the target is gone), the task will be reclassified
to `permanent` after the configured `reclassify_transient_after`
attempts and quarantined.

### `quarantine_log` filling up

Tasks are landing in the quarantine log. Inspect with:

```bash
system logs quarantine
```

Each row has the redacted input payload, the failure
classification, and the error message. The common causes are
policy violations, output validation failures, and model-quality
errors (the model returned a malformed response too many times).

## UI / API

### SSE stream keeps dropping

The SSE endpoint is single-host and uses a long-poll. If your
network goes through a proxy that buffers responses, the stream
will appear to stall. The fix is to either bypass the proxy for
`/api/events/stream` or increase the proxy's read timeout.

### `404` on `/api/...`

The server is running an older build that doesn't know about the
endpoint. Upgrade MAVR and restart `system serve run`.

## Where to look

* Audit log: `system logs audit --campaign <CID>`
* System events: `system logs events --tail 200`
* Quarantine: `system logs quarantine`
* Run bundle: `system report bundle --campaign <CID> --output ./out/`
