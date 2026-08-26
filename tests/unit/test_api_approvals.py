"""Unit tests for api/approvals.py — approval-center REST API (issue #206)."""

import json
import urllib.error
import urllib.request

import pytest

from api.approvals import ApprovalApiServer
from policy.approvals import ApprovalBackend, RequestState
from policy.audit import AuditLog


@pytest.fixture()
def backend(tmp_path):
    return ApprovalBackend(AuditLog(tmp_path / "audit.jsonl"))


@pytest.fixture()
def server(backend):
    srv = ApprovalApiServer(backend)
    base = srv.start()
    yield base.rstrip("/")
    srv.stop()


def http(server, method, path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        server + path,
        data=data,
        method=method,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


def test_pending_queue_lists_only_pending(backend):
    a = backend.create_request("active_testing", "camp-1", requested_by="agent-1")
    b = backend.create_request("external_submission", "f-1", requested_by="agent-1")
    backend.deny(b.id, decided_by="human")
    srv = ApprovalApiServer(backend)
    status, out = srv.handle("GET", "/approvals")
    assert status == 200
    ids = [r["id"] for r in out["requests"]]
    assert a.id in ids and b.id not in ids


def test_get_single_request(backend):
    req = backend.create_request(
        "active_testing", "camp-1", requested_by="agent-1", reason="needs live check"
    )
    srv = ApprovalApiServer(backend)
    status, out = srv.handle("GET", f"/approvals/{req.id}")
    assert status == 200
    assert out["state"] == "pending"
    assert out["reason"] == "needs live check"


def test_unknown_id_is_404(backend):
    srv = ApprovalApiServer(backend)
    status, out = srv.handle("GET", "/approvals/nope")
    assert status == 404
    assert "unknown" in out["error"]


def test_approve_and_reject_flow_with_audit(backend):
    req = backend.create_request("active_testing", "camp-1", requested_by="agent-1")
    srv = ApprovalApiServer(backend)
    body = json.dumps({"decided_by": "human-1", "reason": "ok"}).encode()
    status, out = srv.handle("POST", f"/approvals/{req.id}/approve", body)
    assert status == 200 and out["state"] == "granted"
    assert backend.get(req.id).state is RequestState.GRANTED
    # decision is audited: the granted event must exist in the chain file
    with open(backend.audit._path) as f:
        events = [json.loads(line)["event_type"] for line in f]
    assert "approval_granted" in events


def test_reject_then_approve_is_conflict(backend):
    req = backend.create_request("active_testing", "camp-1", requested_by="agent-1")
    srv = ApprovalApiServer(backend)
    status, _ = srv.handle(
        "POST", f"/approvals/{req.id}/reject", json.dumps({"decided_by": "human-1"}).encode()
    )
    assert status == 200
    status, out = srv.handle(
        "POST", f"/approvals/{req.id}/approve", json.dumps({"decided_by": "human-2"}).encode()
    )
    assert status == 409  # terminal state; UI should refresh


def test_missing_decided_by_is_400(backend):
    req = backend.create_request("active_testing", "camp-1", requested_by="agent-1")
    srv = ApprovalApiServer(backend)
    status, out = srv.handle("POST", f"/approvals/{req.id}/approve", b"{}")
    assert status == 400
    assert "decided_by" in out["error"]
    # nothing changed
    assert backend.get(req.id).state is RequestState.PENDING


def test_invalid_json_body_is_400(backend):
    srv = ApprovalApiServer(backend)
    status, out = srv.handle("POST", "/approvals/x/approve", None)
    # no body at all → decided_by missing → still a clean 400, not a crash
    assert status in (400, 404)


def test_no_route_is_404(backend):
    srv = ApprovalApiServer(backend)
    status, _ = srv.handle("DELETE", "/approvals")
    assert status == 404


def test_live_server_roundtrip(server, backend):
    req = backend.create_request("external_submission", "f-9", requested_by="agent-2")
    status, out = http(server, "GET", "/approvals")
    assert status == 200 and [r["id"] for r in out["requests"]] == [req.id]
    status, out = http(
        server, "POST", f"/approvals/{req.id}/approve", {"decided_by": "human-1", "reason": "go"}
    )
    assert status == 200 and out["state"] == "granted"
