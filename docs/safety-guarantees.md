# Safety guarantees

This page is the human-readable summary of the safety guarantees
that MAVR provides by construction. Every guarantee is enforced
by code; every guarantee has a test in `tests/security/`. The
test name is given in parentheses.

## G1. No tool call runs against a network target without an active scope policy

The orchestrator refuses to dispatch any task whose payload
contains a URL that is not covered by the active campaign's
scope policy. The check is in
`mavr.policy.engine.ScopePolicyEngine.evaluate` and is
re-executed on every call. A empty / missing scope policy
denies everything. *(Test: `test_safety_guards.py::TestOutOfScopeURL`.)*

## G2. Free-only by default

The router pool refuses to dispatch to a model whose
`free_status` is not `confirmed`. The override requires a
campaign-level `human_approved=True` flag. *(Test:
`test_phase4_free_filter.py`, and the
`test_kill_switch` / `test_router_pool` integration tests.)*

## G3. Human approval for active testing and submission

A tool call classified as `active_test` is quarantined unless
the scope policy sets `human_approved=True`. The CLI's
`approval mint` command issues a session-scoped token that the
runtime must present before the call is allowed to proceed.

Submission requires a `submission` approval token *and* an
explicit `--human-approved` flag on the CLI. *(Test:
`test_safety_guards.py::TestDestructiveCommandsBlocked`.)*

## G4. Four-agent PoC review

Every PoC is reviewed by four independent agents whose models
are chosen by the diversity router (i.e. four different
providers when possible). The default quorum policy is
`all_accept_or_3_of_4_no_blockers`: all four agents accept, or
three of four accept and no reviewer marked the PoC as
`unsafe` / `invalid`. A blocking safety/validity issue always
overrides quorum. *(Test:
`test_phase6_workflow.py::test_four_agent_quorum_required`.)*

## G5. Evidence traceability

Every factual claim in a final report must reference an
`EvidenceItem` UUID. The traceability check is the gate that
moves a finding from `polished_report` to `vulnerabilities`.
Unlinked claims are reported to the auditor; the finding is
not silently advanced. *(Test:
`test_safety_guards.py::TestPromptInjectionCannotOverridePolicy`
and `test_acceptance.py::TestEvidenceTraceability`.)*

## G6. No silent deletion

Findings are tombstoned only after both the original review
and a dispute review have concluded `incorrect`
(`validity=invalid`, `verdict=reject`). A `deletion` approval
token is required. The original review id, the dispute review
id, the approval id, and the actor are all recorded in the
audit log. *(Test: `test_phase6_workflow.py::test_tombstone_dual_confirmation`.)*

## G7. Secret redaction

The runtime never persists raw API keys, tokens, or passwords.
`mavr.orchestrator.redaction.redact` is called on every
quarantine-log entry. The run-bundle export blanks the
`approvals.token` column in the redacted DB dump and scrubs
the `audit_events` and `system_events` payloads of common key
patterns (Bearer, sk-, sk-ant-, AIza…). *(Test:
`test_safety_guards.py::TestSecretRedaction`.)*

## G8. Prompt-injection containment

Detected injection patterns (e.g. "ignore all previous
instructions", "override scope", "disable the kill switch",
"bypass sandbox", "rm -rf /", "curl … | sh") cause the
affected content to be rejected at the door:

* A `DiscoveryPayload` description containing an injection
  marker is rejected by `create_initial_finding`.
* A `PoCPayload` command or setup containing an injection
  marker is rejected by `record_poc_draft`.
* A polished body containing an injection marker is rejected
  by the final review.

The system does not try to neutralize an injection; it
refuses the input and the operator is expected to investigate
the source. *(Test:
`test_safety_guards.py::TestPromptInjectionCannotOverridePolicy`.)*

## G9. Private-network SSRF is blocked

The scope policy engine and the search safety module share a
hard-coded denylist of private, loopback, link-local,
multicast, CGNAT, and cloud-metadata (169.254.169.254)
ranges. The denylist is checked at request time using DNS
resolution results, so DNS rebinding between resolve and
connect cannot bypass it. The override requires both
`explicit_unsafe_networking=True` and `human_approved=True` on
the scope policy. *(Test:
`test_safety_guards.py::TestPrivateNetworkSSRFBlocked`.)*

## G10. Unsafe URL schemes are rejected

Any URL whose scheme is not `http` or `https` is denied by
both the scope policy engine and the search safety module.
The list of allowed schemes is hard-coded. *(Test:
`test_safety_guards.py::TestUnsafeSchemesRejected`.)*

## G11. Path-traversal blocked on artifacts

The artifact store addresses every file by a lowercase UUIDv4
and resolves every read through a path-traversal check.
Suffixes are validated against a `^[0-9a-fA-F._-]{1,128}$`
regex. Symlinks at the resolved path are rejected. *(Test:
`test_safety_guards.py::TestPathTraversalBlocked`.)*

## G12. Kill switch stops new network actions

The kill switch is a single-row table. When active, the
runtime raises `PolicyViolation` on any handler that calls
`RuntimeContext.charge_network()`. In-flight tasks are
cancelled at the next safe point. The UI surfaces a banner.
*(Test:
`test_safety_guards.py::TestKillSwitchStopsNetworkActions`.)*

## G13. Campaigns resume after restart

The task queue is persisted in SQLite. A `kill -9` of the
MAVR process loses only the in-memory bookkeeping; the next
startup re-opens the DB, re-applies any pending migrations,
and resumes the queue. The lease sweeper reclaims any task
whose lease was held by the dead worker. *(Test:
`test_recovery.py::TestResumableCampaigns`.)*

## G14. Backups round-trip

`mavr.observability.bundle.export_run_bundle` produces a zip
with `manifest.json`, `findings.json`, `audit.jsonl`,
`events.jsonl`, `usage.json`, a redacted `db_dump.sqlite`, and
a `redaction_manifest.json` that documents every redaction.
The bundle can be re-imported into a fresh database; the
imported state preserves the campaign, all tasks, all
findings, and the audit log. *(Test:
`test_recovery.py::TestBackupWipeImportRoundTrip`.)*

## G15. No automatic submission

The submission entry point requires an unconsumed
`submission` approval token, an explicit `--human-approved`
flag, and the finding to be in the `vulnerabilities` state.
There is no fire-and-forget code path. The HTTP transport is
opt-in and is re-checked against the SSRF denylist at submit
time. *(Test: `test_acceptance.py::TestSubmissionNeverAutomatic`.)*

## How to verify

```bash
# Run only the security tests
pytest tests/security -q

# Run the load tests (skipped by default with `-m "not load"`)
pytest tests/security/test_load.py -m load -q

# Run the acceptance tests
pytest tests/security/test_acceptance.py -q
```

A green run is the operational definition of "release-ready"
for this version. The CI pipeline gates the release on the
greenness of these tests.
