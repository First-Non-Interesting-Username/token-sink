# Policy & Safety Layer

Implementation of PLAN §2.1, §5 and §15 enforcement: scope enforcement,
tool-call gating, and SSRF protections. Enforcement lives in this code —
never as prompt discouragement.

## Layout

| Module | Responsibility |
|---|---|
| `policy/scope.py` | `ScopePolicy` / `TargetSpec` — campaign scope surface + target matching |
| `policy/ssrf.py` | `SSRFGuard` — private/metadata-address blocking with DNS resolution checks |
| `policy/engine.py` | `PolicyEngine` — evaluates every `ToolCallRequest` before execution |

## Design decisions

- **Default-deny targets.** Anything not explicitly in-scope is denied
  (`target_unlisted`). Explicit `out_of_scope` entries always win over
  in-scope matches so an admin can carve one host out of a wildcard.
- **Missing/ambiguous scope is a state, not an error.** `assess_scope()`
  returns DEFINED / AMBIGUOUS / MISSING; the engine refuses everything while
  scope is not DEFINED (§5: agents refuse or pause, never guess).
- **Hard-prohibited actions** (`denial_of_service`, `destructive_mutation`,
  `spam`, `credential_attacks`, `data_exfiltration`) are enforced regardless
  of what a campaign config says — they cannot be configured away.
- **Shell is disabled by default** (§15): it requires the explicit `shell`
  test class grant.
- **Evaluation order matters:** scope classification runs before the SSRF
  guard so an out-of-scope request gets the more actionable explanation;
  the SSRF layer then applies even to in-scope hosts, because a misconfigured
  or injected "in-scope" private address must still fail closed.
- **SSRF check resolves DNS** and treats any answer resolving into
  private/loopback/link-local/metadata space as blocked (fail closed on
  rebinding-style behavior). Literal IPs are checked without DNS. The only
  bypass is `private_network_authorized=True`, which must be set from
  explicit human configuration — never from agent/model input.
- **Blocked events carry IDs.** Every denial records a `BlockedAction` keyed
  by UUID for observability (#23) and the audit log (#15).
- **Injectable SSRF resolver** keeps tests hermetic (no real network).

## Rate limits

`ScopePolicy.rate_limits` carries per-target `RateLimit(max_requests,
per_seconds)` data. Enforcement belongs to the executor/runtime that paces
requests (see PLAN §5); the engine validates scope/method/class/action and
exposes the limits for that layer to consume.

## Tests

- `tests/unit/test_policy_engine.py` — scope matching, gating rules
- `tests/unit/test_ssrf_guard.py` — resolution matrix (loopback, RFC1918,
  link-local/metadata, IPv6 ULA, rebinding, schemes, credentials)
- `tests/safety/test_policy_safety.py` — §19.3 guardrails, marked `safety`
  (never skipped in CI)
