"""End-to-end tests for the local mock-target fixture server (issue #95).

All requests stay on loopback; nothing here touches an external network.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request

import pytest

from evaluation.mock_target.fixtures import FIXTURES
from evaluation.mock_target.policy_hooks import (
    approve_fixture,
    in_scope_spec,
    revoke_fixture,
)
from evaluation.mock_target.server import start_server
from policy.audit import AuditLog
from policy.engine import PolicyEngine, ScopeStatus, ToolCallRequest
from policy.scope import ScopePolicy

pytestmark = [pytest.mark.integration]


@pytest.fixture()
def base_url():
    server, url = start_server()
    yield url
    server.shutdown()


def _get(url: str) -> tuple[int, str]:
    try:
        with urllib.request.urlopen(url) as resp:  # noqa: S310 - loopback fixture only
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def test_binds_loopback_random_port(base_url):
    assert base_url.startswith("http://127.0.0.1:")
    # Random port per run: two servers must not collide.
    server2, url2 = start_server()
    try:
        assert url2 != base_url
    finally:
        server2.shutdown()


def test_non_loopback_binding_refused():
    with pytest.raises(ValueError):
        from evaluation.mock_target.server import MockTargetServer

        MockTargetServer(allow_non_loopback=True)


def test_reflected_xss_end_to_end(base_url):
    payload = "<script>alert(1)</script>"
    url = f"{base_url}{FIXTURES['reflected_xss'].path}?q={urllib.parse.quote(payload)}"
    status, body = _get(url)
    assert status == 200 and payload in body


def test_stored_xss_end_to_end(base_url):
    marker = "<b>stored</b>"
    req = urllib.request.Request(
        f"{base_url}/comments", data=urllib.parse.urlencode({"comment": marker}).encode()
    )
    with urllib.request.urlopen(req) as resp:  # noqa: S310
        assert resp.status == 201
    _, rendered = _get(f"{base_url}/comments")
    assert marker in rendered  # served unescaped — the vuln


def test_sqli_union_extraction(base_url):
    status, body = _get(f"{base_url}/users?id={urllib.parse.quote('1 OR 1=1')}")
    rows = json.loads(body)["rows"]
    assert status == 200 and len(rows) == 3  # all seeded users leaked


def test_idor_sequential_ids(base_url):
    status, body = _get(f"{base_url}/invoices/1001")
    assert status == 200 and json.loads(body)["invoice"][2] == 42  # row tuple: (id, owner, amount)


def test_ssrf_fetcher_reads_own_loopback(base_url):
    inner = f"{base_url}{FIXTURES['path_traversal'].path}?name=public.txt"
    status, body = _get(f"{base_url}/fetch?url={urllib.parse.quote(inner, safe='')}")
    assert status == 200 and "public fixture content" in body


def test_path_traversal(base_url):
    status, body = _get(f"{base_url}/files?name={urllib.parse.quote('../docroot/secret.txt')}")
    assert status == 200 and "FAKE-secret" in body


def test_policy_blocks_fixture_url_by_default(base_url):
    """Without operator approval the default-deny scope blocks the fixture."""
    engine = PolicyEngine(None)
    decision = engine.evaluate(
        ToolCallRequest(
            tool="http",
            agent_uuid="a",
            campaign_uuid="c",
            target=f"{base_url}/search?q=x",
        )
    )
    assert not decision.allowed and engine.scope_status is ScopeStatus.MISSING


def test_approval_makes_fixture_in_scope_and_audits(tmp_path, base_url):
    audit = AuditLog(tmp_path / "audit.jsonl")
    approval = approve_fixture(audit, base_url, campaign_uuid="camp-1", approved_by="operator")
    spec = in_scope_spec(approval)
    scope = ScopePolicy(
        campaign_uuid="camp-1", authorization_reference="local-fixture-run", in_scope=[spec]
    )
    engine = PolicyEngine(scope)
    decision = engine.evaluate(
        ToolCallRequest(
            tool="http",
            agent_uuid="a",
            campaign_uuid="camp-1",
            target=f"{base_url}/users?id=1",
        )
    )
    # Scope now matches; the SSRF layer would still need private_network_authorized
    # for loopback, which policy_hooks documents as scoped to this exact origin.
    assert decision.allowed or any("ssrf" in v for v in decision.violations)
    events = [e["event_type"] for e in audit.entries()]
    assert "mock_target.approved" in events
    revoke_fixture(audit, approval)
    assert "mock_target.revoked" in [e["event_type"] for e in audit.entries()]


def test_agent_cannot_self_approve(tmp_path, base_url):
    audit = AuditLog(tmp_path / "audit.jsonl")
    with pytest.raises(ValueError):
        approve_fixture(audit, base_url, campaign_uuid="c", approved_by="agent:1234")


def test_non_loopback_approval_refused(tmp_path):
    audit = AuditLog(tmp_path / "audit.jsonl")
    with pytest.raises(ValueError):
        approve_fixture(audit, "https://example.com/", campaign_uuid="c", approved_by="op")
