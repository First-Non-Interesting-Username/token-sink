# Local mock-target fixture server (issue #95, PLAN §10.4)

A deliberately vulnerable demo web app for PoC development and testing.
Loopback-only, deterministic (seeded data), stdlib-only.

## Run

```python
from evaluation.mock_target.server import start_server

server, base_url = start_server()  # random free loopback port
print(base_url)
...
server.shutdown()
```

Non-loopback binding is refused unconditionally (`allow_non_loopback=True`
raises) — the fixture must never be reachable from outside the machine.

## Fixture catalog

| fixture | class | route | notes |
|---|---|---|---|
| `reflected_xss` | xss | `/search?q=` | query echoed unescaped |
| `stored_xss` | xss | `POST /comments`, view at `/comments` | bodies rendered raw |
| `sqli` | sqli | `/users?id=` | interpolated into SQLite query |
| `idor` | access_control | `/invoices/<id>` | sequential ids, no ownership check |
| `ssrf_fetcher` | ssrf | `/fetch?url=` | fetches any URL (use against itself) |
| `path_traversal` | path_traversal | `/files?name=` | joins user input to docroot |

Each entry in `fixtures.py` documents the safe exploitation boundary and the
evidence artifacts a reproduction produces. Seeded data is fixed
(`seed_db()`), so reproductions are stable across runs. All "secrets" in
docroot are fake (`changeme`-style).

## Policy-layer integration

Fixture URLs are loopback addresses, so default-deny scope + the SSRF guard
block them until an operator approves the running instance:

```python
from evaluation.mock_target.policy_hooks import approve_fixture, in_scope_spec

approval = approve_fixture(audit_log, base_url, campaign_uuid=..., approved_by="operator")
scope.in_scope.append(in_scope_spec(approval))
```

- Approvals are loopback-only and require a human actor — `agent:` actors
  are rejected, agents cannot self-approve.
- Every approval/revocation is appended to the tamper-evident audit log
  (§15), even though the target is local.
