# Changelog

All notable changes to MAVR are documented in this file. The format
is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] — 2026-08-25

First public release of MAVR (Multi-Agent Security Vulnerability
Research System). This release is the end of the eight-phase build
cycle and meets the spec §21 Definition of Done.

### Highlights

* **CLI (`system`)** with subcommands for `init`, `doctor`, `serve`,
  `campaign`, `provider`, `model`, `finding`, `report`, `approval`,
  and `logs`.
* **Local web UI** (FastAPI + SSE) with dashboards, the kill-switch
  banner, and the finding state-machine inspector.
* **Local web server** is bound to `127.0.0.1` by default and has no
  built-in authentication; expose it only over a trusted tunnel.
* **Scope policy engine** with a hard-coded private-network denylist
  (loopback, RFC1918, link-local, multicast, CGNAT, cloud metadata),
  enforced at request time using DNS resolution.
* **Task queue** with atomic lease acquisition, heartbeats, an
  in-process sweeper, DAG dependencies, and an exponential-backoff
  retry path with reclassification to permanent on budget exhaustion.
* **Provider interface** with adapters for OpenAI-compatible endpoints
  (Gemini, OpenCode Zen, Kilo gateway, HuggingFace, custom) and an
  in-process `MockAdapter` for tests.
* **Router pool** with three default policies (`best_score_within_budget`,
  `consensus`, `fastest_eligible`, `diversity`), free-only filtering,
  per-(provider, model) circuit breakers, and a dead-letter queue.
* **Usage accounting** that records every call, splits free vs paid,
  and rolls up totals by campaign and by model.
* **Search + extraction** (ddgs) with HTML sanitization, path-traversal
  guards, and a content-addressed evidence store.
* **Finding workflow**: discovery → first-cycle review → impact →
  PoC draft → four-agent review (with quorum + dispute + safety
  overrides) → polish → final review (claim↔evidence traceability)
  → tombstone safeguards (dual confirmation).
* **Approvals** for active testing, submission, scope change, and
  deletion. Submission is never automatic; the HTTP transport is
  opt-in and re-checked against the SSRF denylist at submit time.
* **Run-bundle export** for handoff to a remote reviewer: redacted
  SQLite dump, `manifest.json`, `findings.json`, `audit.jsonl`,
  `events.jsonl`, `usage.json`, `artifacts_index.json`, and a
  `redaction_manifest.json` that documents every redaction.
* **Observability**: structlog JSON output, SSE event stream, audit
  log, run-bundle export, and Prometheus-style metrics.

### Safety guarantees (all enforced by code, all covered by tests)

1. No tool call runs without an active scope policy (G1).
2. Free-only routing by default; paid requires a campaign-level
   `human_approved` flag (G2).
3. Active testing and submission require a human-approval token (G3).
4. Four-agent PoC review with default quorum
   `all_accept_or_3_of_4_no_blockers` (G4).
5. Every claim in a final report traces to an evidence UUID or is
   labeled as analysis (G5).
6. No silent deletion — dual confirmation required (G6).
7. Secret redaction in quarantine log and run-bundle export (G7).
8. Prompt-injection containment in finding bodies, PoC commands, and
   polished reports (G8).
9. Private-network SSRF blocked at the policy and DNS-resolution
   layers (G9).
10. Unsafe URL schemes rejected (G10).
11. Path-traversal blocked on artifacts (G11).
12. Kill switch stops new network actions (G12).
13. Campaigns resume after `kill -9` (G13).
14. Backups round-trip (G14).
15. No automatic submission (G15).

### Tests

* 384 tests passing across unit, integration, security, load, and
  acceptance categories.
* `tests/security/` covers the eight hard-safety properties above,
  the recovery / backup tests, the load tests, the offline
  evaluation fixtures, and the spec §21 acceptance tests.
* Load tests are gated behind the `load` pytest marker; the default
  suite (`pytest -m "not load"`) finishes in under 30 seconds on
  developer hardware.

### Packaging

* Pure-Python wheel and sdist.
* `pyproject.toml` declares the build backend and the runtime /
  dev dependencies.
* `make install` / `make wheel` / `make sdist` / `make dist` for
  developers.
* `scripts/install.sh` is the non-make equivalent.
* Optional PyInstaller single-file binary via `make pyinstaller`.
* Supported Python versions: 3.11 and 3.12. Tested on Linux; macOS
  should work with the same toolchain.

### Known limitations

* macOS and Windows are not officially tested.
* The PyInstaller binary ships with the SQLite native extension from
  the Python standard library and does not bundle a custom OpenSSL
  trust store.
* Out-of-band verification of the model catalog is required before
  each release; the catalog is a trust root.

### Documentation

* `docs/architecture.md`
* `docs/installation.md`
* `docs/quickstart.md`
* `docs/configuration.md`
* `docs/scope-policy.md`
* `docs/providers.md`
* `docs/troubleshooting.md`
* `docs/threat-model.md`
* `docs/safety-guarantees.md`
* `docs/faq.md`

### Security advisories

None.

[0.1.0]: https://github.com/your-org/mavr/releases/tag/v0.1.0
