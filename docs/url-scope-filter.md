# URL Scope Filter (PLAN §9, issue #103)

`policy/url_filter.py` is the single chokepoint that decides whether a
discovered URL may be acted on. Search (#18/#19), extraction, and the policy
engine (#8) all route URL decisions through it — nothing else implements
scope matching for URLs.

## API

```python
from policy.url_filter import UrlScopeFilter, ScopeVerdict

f = UrlScopeFilter(
    in_scope=["example.com", "https://api.example.com/v2", "10.0.0.0/8"],
    out_of_scope=["admin.example.com", "https://example.com/private"],
)
c = f.check("https://example.com/page")  # -> Classification
c = f.check_redirect_chain([u1, u2])  # every hop re-checked
```

Verdicts:

- `IN_SCOPE` — matches an in-scope entry; proceed (SSRF guard still applies
  upstream).
- `OUT_OF_SCOPE` — explicitly denied (out-of-scope entry, bad scheme,
  embedded userinfo) or observed resolving to a private address.
- `AMBIGUOUS` — unlisted (default-deny) or malformed. Per §5 this means
  refuse/pause with an actionable reason; agents never guess.

Out-of-scope always wins over in-scope, so an admin can carve one path or
subdomain out of a wildcard grant.

## Matching rules

- **Domain entries** (`example.com`) match the host plus any subdomain;
  case-insensitive; a trailing-dot FQDN (`example.com.`) normalizes away so
  it can't bypass or dodge scope.
- **URL prefix entries** (`https://api.example.com/v2`) match the exact URL
  or any deeper path segment (`/v2/users` yes, `/v22/users` no). Default
  ports normalize away; fragments are ignored.
- **CIDR entries** (`10.0.0.0/8`) match IP-literal hosts only.
- **Schemes**: http/https only (allowlist per §15); anything else is
  OUT_OF_SCOPE.
- **Userinfo** (`https://user@host/...`, incl. the
  `https://in.scope@evil.host/` confusion trick) is refused outright.
- **IDN/punycode**: both the URL host and domain scope entries are decoded
  to their Unicode form before comparison, so `xn--...` wire forms match
  Unicode scope entries and homoglyph lookalikes simply don't match
  (they fall through to default-deny).

## Redirect chains

`check_redirect_chain(urls)` re-classifies EVERY hop; the first non-IN_SCOPE
hop fails the chain with its `hop_index`. Callers that resolve DNS can pass
`private_ip_hosts={names}` to block hops to hosts that resolved to private
addresses even when the name itself is in scope (rebinding defense,
interplay with #26 / `policy/ssrf.py`).

## Tests

`tests/unit/test_url_scope_filter.py` — 27 tests covering all of the above
including the tricky cases called out in the issue (IDN lookalikes,
trailing dots, userinfo tricks, port variations, per-hop redirect checks).
