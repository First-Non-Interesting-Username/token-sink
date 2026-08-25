# system doctor

`python -m cli doctor [--config PATH] [--json] [--skip-network]` implements the
§17 diagnostics command (issue #93). It gates every first-run experience.

## Behavior

- **Report-all**: every check runs; a failure never aborts the rest. All
  results are printed in one pass.
- **Exit codes**: `0` all checks pass, `2` at least one warning, `1` at least
  one failure. Scripts/CI should branch on these.
- **Output**: human-readable by default, `--json` for tooling (shape:
  `{status, exit_code, checks:[{name,status,detail,data}]}`).

## Checks

| Check | Fail when | Notes |
|---|---|---|
| python-version | interpreter < 3.11 | matches pyproject |
| module:ddgs | not importable | soft (WARN) until search subsystem enabled |
| command:curl | not on PATH | used by extraction (PLAN §9) |
| config | parse/validation errors | reports ALL §16 validation errors; missing file is WARN with hint |
| db-path | sqlite can't open/create | creates parent dirs |
| artifact-dir | not writable | created if missing; probe file cleaned up |
| disk-space | < 1 GiB free | WARN below threshold, FAIL near-zero |
| keyring | unusable backend / absent | always WARN only — env-var refs still work (#29) |
| provider-endpoints | unreachable | WARN only (offline dev is valid); probes provider APIs ONLY, never campaign targets |
| ui-port | host:port not bindable | uses configured server section |
| schema-version | DB newer than build | reads `PRAGMA user_version`; fresh DB = WARN |

## Safety notes

The network check contacts only well-known provider API endpoints to prove
egress/DNS/TLS work. It must never be pointed at campaign targets — targets
only exist inside an authorized campaign context. `--skip-network` disables
all egress probing for offline environments.
