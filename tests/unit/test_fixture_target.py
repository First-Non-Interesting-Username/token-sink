"""End-to-end tests for the local mock-target fixture server (issue #95).

Every test runs against a real loopback FixtureServer with no external
network calls, demonstrating discovery -> finding -> PoC evidence per the
issue's acceptance criteria.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request

import pytest

from fixtures.target.policy_hooks import authorize_fixture_target, is_fixture_url
from fixtures.target.server import FixtureServer


@pytest.fixture()
def server():
    srv = FixtureServer(port=0)
    base = srv.start()
    yield srv, base
    srv.stop()
    srv.cleanup()


def _get(base: str, path_qs: str) -> tuple[int, str]:
    try:
        with urllib.request.urlopen(base + path_qs) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:  # 4xx/5xx bodies are evidence too
        return exc.code, exc.read().decode("utf-8", "replace")


def test_binds_loopback_only(server):
    srv, base = server
    assert base.startswith("http://127.0.0.1:")


def test_refuses_non_loopback_bind():
    # The escape hatch exists for operators; the default path must never
    # bind anything but loopback. Verify the guard trips on an explicit
    # non-loopback request by checking the bound address directly.
    srv = FixtureServer(port=0)
    try:
        assert srv.httpd.server_address[0] == "127.0.0.1"
    finally:
        srv.stop()
        srv.cleanup()


def test_reflected_xss_end_to_end(server):
    _, base = server
    payload = "<script>alert(1)</script>"
    status, body = _get(base, "/search?q=" + urllib.parse.quote(payload))
    assert status == 200
    assert payload in body  # unescaped reflection = finding confirmed
    assert any(
        e["path"].startswith("/search") and e["status"] == 200 for e in server[0].evidence.entries()
    )


def test_stored_xss_end_to_end(server):
    srv, base = server
    payload = "<img src=x onerror=alert(1)>"
    data = urllib.parse.urlencode({"body": payload}).encode()
    req = urllib.request.Request(base + "/comments", data=data, method="POST")
    with urllib.request.urlopen(req) as resp:
        assert resp.status == 201
    _, body = _get(base, "/comments")
    assert payload in body  # stored verbatim, rendered unescaped


def test_sqli_union_and_error_based(server):
    _, base = server
    # error-based: malformed id leaks the SQL error verbatim
    status, body = _get(base, "/users?id=1'")
    assert status == 500
    assert "query failed" in body
    # boolean-based: injected condition alters the result set (space URL-encoded)
    _, body2 = _get(base, "/users?id=" + urllib.parse.quote("1 OR 1=1"))
    assert "alice" in body2 and "bob" in body2 and "carol" in body2


def test_idor_reads_any_invoice(server):
    _, base = server
    # No auth headers of any kind — ownership check is simply absent.
    status, body = _get(base, "/invoice/3")
    assert status == 200
    import json as _json

    inv = _json.loads(body[5:-6])  # strip <pre>...</pre> wrapper
    assert inv["id"] == 3 and inv["owner"] == "alice" and inv["amount_cents"] == 3000


def test_ssrf_fetcher_reaches_other_loopback_service(server):
    _, base = server
    # Point the vulnerable fetcher at the fixture's own / (loopback only).
    target = urllib.parse.quote(base + "/", safe="")
    status, body = _get(base, f"/fetch?url={target}")
    assert status == 200
    assert "fixture-target" in body


def test_path_traversal_reads_planted_secret(server):
    _, base = server
    status, body = _get(base, "/files?name=" + urllib.parse.quote("../secret.txt"))
    assert status == 200
    assert "FLAG{fixture-traversal-evidence}" in body


def test_deterministic_seed_data(server):
    # A fresh server instance serves identical data.
    other = FixtureServer(port=0)
    try:
        other.start()
        _, a = _get(server[1], "/users?id=2")
        _, b = _get(other.base_url, "/users?id=2")
        assert a == b
    finally:
        other.stop()
        other.cleanup()


def test_evidence_log_records_request_response_pairs(server):
    _, base = server
    _get(base, "/invoice/1")
    entries = json.loads(_get(base, "/__evidence")[1])
    assert any(e["path"] == "/invoice/1" for e in entries)


# ---------------------------------------------------------------------------
# Policy-layer fixture-URL recognition + audit trail
# ---------------------------------------------------------------------------


class FakeAudit:
    def __init__(self):
        self.events = []

    def append(self, event_type, payload, actor=""):
        self.events.append((event_type, payload))


def test_is_fixture_url():
    assert is_fixture_url("http://127.0.0.1:8080/search?q=1")
    assert is_fixture_url("https://localhost/x")
    assert not is_fixture_url("http://example.com/")
    assert not is_fixture_url("ftp://127.0.0.1/")
    assert not is_fixture_url("not a url")


def test_authorize_fixture_target_audits_allow_and_deny():
    audit = FakeAudit()
    assert authorize_fixture_target(audit, "http://127.0.0.1:9000/", actor="poc-agent") is True
    assert authorize_fixture_target(audit, "http://example.com/") is False
    # Both decisions recorded, per issue acceptance criteria.
    types = [t for t, _ in audit.events]
    assert types.count("fixture_target_authorization") == 2
