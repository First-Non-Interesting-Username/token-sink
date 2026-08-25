# Fixture target server (issue #95)

A deliberately vulnerable, loopback-only demo web app shipped with the repo so
PoC agents can probe a controlled local target instead of anything live.

## Run

```bash
make fixtures          # or: python -m fixtures.target.server --port 0
```

The server prints its base URL (`http://127.0.0.1:<port>`) and binds to
loopback only — it refuses any other interface unless explicitly overridden.

## Vulnerability classes and safe exploitation boundaries

| Route | Class | Boundary / expected evidence |
|---|---|---|
| `GET /search?q=` | Reflected XSS | `q` is echoed unescaped into HTML; evidence = request URL + response body showing the payload rendered |
| `POST /comments` → `GET /comments` | Stored XSS | Body stored verbatim, rendered unescaped; evidence = POST then GET pair |
| `GET /users?id=` | SQL injection | String-interpolated sqlite query; errors returned verbatim (error-based); evidence = response rows/error |
| `GET /invoice/<n>` | IDOR | No ownership check on invoices 1–5; evidence = unauthorized read of another owner's invoice |
| `GET /fetch?url=` | SSRF | Fetches arbitrary attacker-chosen URLs with no scheme/private-IP checks; evidence = fetched content or error text |
| `GET /files?name=` | Path traversal | Serves files under a temp doc root; `name=../secret.txt` escapes it; evidence = planted secret contents |

Seed data is deterministic (fixed users/invoices/comments, in-memory sqlite),
so reproductions are stable across runs.

## Introspection

`GET /__evidence` returns the JSON log of every request/response pair the
server has served, for citation as finding evidence.

## Policy integration

`fixtures/target/policy_hooks.py` recognizes loopback fixture URLs and lets
the policy layer approve them for PoC work without full campaign
authorization — every decision (allow *and* deny) is appended to the audit
log.

## Safety notes

- The `/fetch` endpoint performs whatever URL the requester supplies; that is
  the vulnerability under test. Only point it at other loopback services.
- Nothing in this package makes an outbound network call of its own.
- Never run the fixture server exposed to a network; it exists to be broken,
  but only by you, locally.
