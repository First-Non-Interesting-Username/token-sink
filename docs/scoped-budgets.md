# Scoped budget enforcement (issue #106, PLAN §5/§6/§14)

The per-agent enforcer (`budgets/__init__.py`, issue #141) handles one
agent's lifetime caps. `budgets/scoped.py` adds the *scope hierarchy* and
the semantics that make budgets enforceable:

## Scopes

Three nested scopes share the same four dimensions (tokens, requests,
wall-clock seconds, tool calls): **global**, **campaign**, **agent**.
Pre-flight checks run outermost-first; a refusal at any scope blocks the
call before dispatch with a typed `ScopedBudgetExhausted` — never
run-then-bill.

## Reservations (atomicity)

Concurrent callers must `reserve()` before dispatch. The manager holds a
single lock: it validates every scope can afford the request, then places
holds on all scopes atomically. If any scope refuses, nothing is held.
Two parallel agents cannot both spend the last 1k tokens — the second
reservation raises.

Reservation lifecycle:

- `commit(tokens=..., ...)` — bills *actual* usage across all held scopes
  and drops the hold. Over-reservation headroom returns automatically.
- `release()` — failure/timeout path: the hold is dropped, nothing is
  billed. A timed-out call that already streamed tokens does an explicit
  partial commit of just that amount.

## Warnings vs hard caps

Crossing 80% of any dimension emits a `budget_warning` event; only 100%
blocks. Campaign-scope exhaustion emits `campaign_exhausted` and records a
pause entry — pause + operator notification, not a silent stop.

## Persistence

`snapshot()` returns spent usage per scope; `restore()` applies it to a
fresh manager but only ever *raises* spent values (max-merge), so usage
spent between snapshot and crash is never unspent by a restart.
