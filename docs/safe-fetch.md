# Safe-fetch pipeline (PLAN §9/§15, issue #124)

`search/safe_fetch.py` gates every HTTP fetch the system makes. The policy
engine (`policy/engine.py`, #8) decides whether a *tool call* is allowed;
this module decides whether a specific *request* is allowed and under which
limits.

## Layers (in evaluation order)

1. **URL validation** — scheme allowlist (http/https only), userinfo
   rejection, host normalization. IPv4 shorthands (decimal `2130706433`,
   hex/octal mixes, short forms like `127.1`) are expanded to dotted-quad
   before any check, because they bypass naive string-level private-range
   matching. IPv6-mapped IPv4 (`::ffff:10.0.0.1`) is judged by its IPv4 side.
2. **Scope filter** — every URL must classify as `in` against the campaign's
   `ScopePolicy`. `unlisted` is refused, never guessed; explicit out-of-scope
   entries always win.
3. **SSRF** — delegates to `policy/ssrf.py`'s `SSRFGuard` on the normalized
   URL: literal-IP checks plus DNS resolution with fail-closed treatment of
   any private answer (rebinding defense).
4. **Redirect policy** — `check_redirect_chain()` re-validates every hop from
   scratch (scope AND SSRF); hops capped at `FetchLimits.max_redirect_hops`.
   A redirect never inherits trust from the URL that produced it.
5. **Response limits** — `response_allowed()` checks content-type allowlist,
   max bytes, and elapsed-time budget.

## TOCTOU

DNS can change between validation and connect. `FetchVerdict.
resolved_addresses` carries the addresses that were checked; the HTTP layer
should pin the connection to one of them or re-validate post-resolution.

## Tests

`tests/unit/test_safe_fetch.py` — one case per bypass class from issue #124:
decimal/octal/hex/short IPv4 encodings, IPv6 loopback and mapped-IPv4,
metadata service by name, mocked DNS rebind (mixed public/private answers),
redirect-to-private, redirect-to-out-of-scope, relative Locations, hop cap,
and response-limit checks.
