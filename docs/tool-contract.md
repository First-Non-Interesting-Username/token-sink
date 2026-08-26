# Tool Contract: registry & enforcement (PLAN §6, §15, §18)

How tool calls made by agents are validated before anything executes
(issue #155). Read alongside [safety-and-scope.md](safety-and-scope.md)
(policy engine) and [failure-handling.md](failure-handling.md).

## Components

- `tools/registry.py` — `ToolSignature` (name, version, typed params with
  required/default, return descriptor) and `ToolRegistry`, the single source
  of truth. `describe_for_prompt()` gives agents a machine-readable listing so
  models only ever see tools that actually exist.
- `tools/gate.py` — `ToolGate.dispatch(fn, name, args)`: the ONLY path from a
  model's tool call to execution.

## Validation rules (before dispatch, always)

| Condition | Rejection code |
|---|---|
| Tool not registered (hallucinated) | `unknown_tool` |
| Arguments not an object | `wrong_type` |
| Required param missing / wrong type | `invalid_arguments` |
| Undeclared parameter in **strict** mode | `invalid_arguments` |
| Payload over size cap | `payload_too_large` |
| Breaker open for this agent/model | `breaker_open` |

Rejections are structured (`Rejection.as_feedback()`) and returned to the
model as bounded feedback — the caller retries at most
`ToolGate.max_retries` times before escalating through the §18 failure
matrix (`MALFORMED_OUTPUT`). Rejected calls never crash and never execute;
this is asserted directly by tests.

### Strict mode

Strict (the default) rejects undeclared parameters rather than silently
dropping them — silent dropping can change semantics (e.g. a dropped
`dry_run=False`). Non-strict still drops unknown keys; unvalidated input is
never forwarded either way.

Type strictness detail: Python's `bool` subclasses `int`, so a boolean value
is rejected for integer/number parameters explicitly.

## Repeated-violation circuit breaker

An agent+model exceeding `BreakerConfig.max_violations` malformed calls
within `window_s` is paused for `cooldown_s`; even valid calls are refused
(without executing) during cooldown, and the trip emits an audit event via
`policy.audit`. The breaker is keyed per agent+model pair — one bad model
cannot lock out others.

## Score hook

`ToolGate.malformed_by_model` / `total_by_model` count malformed-call rates
per `(model_id, provider_id)` for the §8.3 tool-use reliability score
category and benchmark suite (#86/#17).

Related: PLAN §6, §8.3, §15, §18; issues #155, #91, #58.
