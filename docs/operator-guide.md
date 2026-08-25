# Operator Guide

Status: **planning-stage documentation.** Commands below follow the CLI
surface defined in [PLAN.md §17](../PLAN.md); exact names may change as the
implementation lands, and this guide will be updated when they do.

## What this tool is (and is not)

A locally hosted orchestration system for **authorized** security research
(e.g. bug bounty programs with clear rules such as
[Hack Club Security](https://security.hackclub.com/)). It only operates
against explicitly authorized, in-scope targets. Using it against systems you
are not authorized to test is prohibited and unsupported.

## Install

- Linux only. Prerequisites: a supported Python 3 runtime and `curl` for the
  extraction subsystem (packaging/install story tracked in issue #34).
- After install, run the environment check:

```sh
system doctor
```

`doctor` verifies prerequisites, configuration validity, credential access,
and reports problems before any workers start. Full check list, exit codes
(0 pass / 2 warn / 1 fail), and the `--json` flag are documented in
[docs/system-doctor.md](docs/system-doctor.md). Run it as
`python -m cli doctor [--config PATH] [--skip-network]`.

## Configuration

Configuration lives in a YAML/TOML file covering (PLAN §16): server host/port,
database + artifact paths, provider credential references, provider/model
allowlists, free-only mode, router count/concurrency, agent budgets/timeouts,
search/extraction settings, campaign defaults, scope & active-testing policy,
review quorum, retention/redaction, logging/telemetry.

Rules of thumb:

- **Secrets never go in the config file itself.** Reference credentials stored
  in your OS credential store or protected local configuration; they must
  never appear in prompts, logs, reports, exports, or git.
- Config is validated at startup; all errors are reported before workers
  launch — fix everything it lists rather than silencing warnings.
- Keep `free-only: true` unless you explicitly want paid models routable;
  free-only routing can never select a paid or unknown-free-status model.

## Running

```sh
system init            # create project layout / DB
system doctor          # verify environment
system serve           # start server + worker runtime; prints local UI URL
```

The UI binds to localhost by default. Do not expose it to other machines
without understanding the auth implications (issue #32 documents the API's
local-only default).

### Campaign lifecycle

```sh
system campaign create          # define scope, authorization ref, budgets
system campaign list
system campaign start <id>
system campaign pause <id>
system campaign stop <id>
system campaign export <id>     # portable bundle (resumable elsewhere)
```

Every campaign requires an explicit target scope, authorization source,
allowed/prohibited actions, rate limits, and budgets before it will start.
Missing or ambiguous scope is a defined state: agents refuse/pause rather than
guess. See [Safety & scope authoring](safety-and-scope.md) before writing one.

### Providers & models

```sh
system provider list
system provider test <id>       # connectivity check; never prints secrets
system model benchmark          # versioned benchmark suite
```

Partly-free gateways (OpenCode Zen, Kilo Gateway) only expose models with
confirmed free-status metadata; unknown-status models stay out of free-only
routing by design.

### Findings, reports, logs

```sh
system finding list
system finding inspect <id>
system finding approve <id>     # human approval gates (see below)
system finding reject <id>
system report export <id>
system logs
```

## Human control points

You are the approval authority. The system requires explicit human approval
before (PLAN §2.5):

- enabling/performing active testing,
- executing a PoC that could affect a live target,
- submitting anything externally (submission is *never* automatic),
- deleting findings (which additionally needs two independent reviewer
  conclusions of "incorrect"),
- changing campaign scope.

Runtime controls available at all times:

- **Global kill switch** — cancels all active tasks immediately and prevents
  new network actions; works even mid-provider-request. Available from both
  the UI and CLI.
- Per-campaign pause/resume/stop; per-agent cancel/retry; finding quarantine.

Approvals pending, blocked actions, and full audit history appear in the
UI "Policy & approvals" view; every control emits a tamper-evident audit
event.

## Reading the dashboards

- **Dashboard**: campaigns, agent/task states, findings by lifecycle stage,
  alerts/approvals.
- **Live activity**: each agent's UUID, role, parent, task, model, status.
- **Finding workspace**: lifecycle timeline, evidence provenance, review
  opinions + dissent, version diffs, PoC safety status.
- **Provider/model**: health, latency, errors, quotas, free/paid class,
  scores with confidence.
- **Usage/costs**: tokens/requests by provider/model/campaign/agent/task and
  time range — free-tier usage always separated from paid.
- **Logs & diagnostics**: structured logs with correlation IDs, exportable
  run bundle.

## Reliability expectations

- Restarting the application does not lose campaign or finding state;
  campaigns resume after restart (PLAN §21 acceptance).
- Failed inputs/outputs are preserved for diagnosis with secrets/sensitive
  data redacted; retries happen only for classified transient failures.
- Export bundles pass through the redaction pipeline; expired artifacts are
  securely deleted with audit events.

## Safety checklist before first run

1. Written authorization exists for every in-scope target.
2. Out-of-scope targets are explicitly listed, not merely absent from scope.
3. Rate limits and budgets set to conservative values for the target's rules.
4. Active testing disabled until you have reviewed discovery output.
5. `system doctor` clean; kill switch location known to whoever is on duty.
