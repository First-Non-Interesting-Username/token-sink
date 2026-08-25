# Policy & Human Controls (`policy/`)

Implements the human-control slice of PLAN.md §2.5 and §15 (issue #30), plus
the tamper-evident audit log required by §15. The scope-enforcement/policy
engine itself is tracked separately (issue #8); these modules are the control
surface that operates on top of it.

## Modules

- `kill_switch.py` — process-global, latched kill switch. Once engaged,
  every network/tool action routed through `KillSwitch.check()`/`gate()`
  refuses with `KillSwitchActive`. Runtime components register an
  `on_activate` hook that cancels their in-flight tasks; hooks must be
  fail-safe (one raising hook cannot stop others from cancelling).
  There is **no automatic reset** — only an explicit operator
  `deactivate()` — because a safety control that silently re-arms itself is
  worse than one that stays off.
- `controls.py` — `Controls`: campaign pause/resume/stop, agent cancel/retry,
  finding quarantine, and approval gates.
  - Cancellation propagates transitively to subagents via the `parent`
    link each agent record may carry (PLAN §6).
  - Quarantine preserves the finding record with a tombstone flag — it is
    never a silent delete (§10.5 deletion safeguards).
  - Approval gates guard exactly the PLAN §2.5 actions:
    `active_testing`, `poc_execution_live_target`, `external_submission`,
    `finding_deletion`, `scope_change`. Guarded actions proceed only after an
    explicit human grant, and even granted actions are refused while the kill
    switch is engaged.
- `audit.py` — append-only, hash-chained JSONL audit log. Each record embeds
  the hash of its predecessor; `AuditLog.verify()` detects any retroactive
  edit or deletion. Every control action emits one audit event with actor,
  reason, and payload.
- `cli.py` — non-interactive CLI equivalents (§17): `system controls
  kill-switch | campaign-pause|resume|stop | agent-cancel|retry |
  finding-quarantine | approval-decide | approvals-pending | audit-verify`.
  Commands print machine-readable JSON and exit nonzero with
  `{"error": ...}` on refusal.

## Wiring

The application entrypoint creates shared `AuditLog`, `KillSwitch`, and
`Controls` instances and passes them to the runtime, API layer (#32), and CLI
(#20). Network egress paths (search/extraction #18/#19, provider adapters
#14) must wrap their calls in `KillSwitch.gate()` so activation takes effect
immediately, including mid-request cancellation through `on_activate` hooks.
