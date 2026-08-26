"""Tests for the agent activity view (issue #169): ui/activity_board.py +
api/agent_activity.py."""

import json
import urllib.error
import urllib.request

import pytest

from api.agent_activity import AgentActivityApiServer
from ui.activity_board import AgentActivityBoard


@pytest.fixture
def board():
    b = AgentActivityBoard(stale_threshold_s=60)
    b.upsert(
        "a-1", role="discovery", campaign_uuid="camp-1", model="m1", provider="p1", event="spawned"
    )
    b.upsert("a-2", role="review", parent_uuid="a-1", campaign_uuid="camp-1")
    b.upsert("a-3", role="poc", campaign_uuid="camp-2")
    return b


# -- read model ---------------------------------------------------------------


def test_snapshot_filters_by_campaign(board):
    uuids = [c.agent_uuid for c in board.snapshot(campaign="camp-1")]
    assert uuids == ["a-1", "a-2"]


def test_snapshot_filters_by_role_and_status(board):
    board.mark_task("a-1", "t-9", started=True)
    assert [c.agent_uuid for c in board.snapshot(role="discovery")] == ["a-1"]
    assert [c.agent_uuid for c in board.snapshot(status="running")] == ["a-1"]


def test_parent_link_records_subagent(board):
    card = board.drilldown("a-1")
    assert "a-2" in card["subagent_uuids"]
    child = board.drilldown("a-2")
    assert child["parent_uuid"] == "a-1"


def test_task_lifecycle_updates_card(board):
    board.mark_task("a-3", "t-1", started=True)
    card = board.drilldown("a-3")
    assert card["status"] == "running"
    assert card["current_task_id"] == "t-1"
    assert card["elapsed_s"] is not None
    board.mark_task("a-3", "t-1", started=False)
    card = board.drilldown("a-3")
    assert card["status"] == "idle"
    assert card["task_history"][0]["status"] == "finished"


def test_blocked_agent_links_blocker(board):
    board.mark_blocked("a-3", kind="approval", ref="apr-7", reason="live target")
    card = board.drilldown("a-3")
    assert card["status"] == "blocked"
    assert card["blocked_by"] == {"kind": "approval", "ref": "apr-7", "reason": "live target"}
    assert "apr-7" in card["latest_event"]


def test_invalid_status_rejected(board):
    with pytest.raises(ValueError):
        board.mark_status("a-1", "vibrating")


def test_stale_heartbeat_flagged(board, monkeypatch):
    from datetime import UTC, datetime, timedelta

    card = board._agents["a-1"]
    card.last_heartbeat = datetime.now(UTC) - timedelta(seconds=600)
    snap = {c.agent_uuid: board.card(c) for c in board.snapshot()}
    assert snap["a-1"]["stale"] is True
    assert snap["a-2"]["stale"] is False


# -- HTTP API -----------------------------------------------------------------


@pytest.fixture
def server(board):
    s = AgentActivityApiServer(board)
    port = s.start()
    yield f"http://127.0.0.1:{port}", s
    s.stop()


def _get(url):
    with urllib.request.urlopen(url) as resp:
        return resp.status, json.loads(resp.read())


def test_api_lists_agents(server):
    url, _ = server
    status, body = _get(f"{url}/agents")
    assert status == 200
    assert len(body["agents"]) == 3


def test_api_drilldown_and_404(server):
    url, _ = server
    try:
        status, body = _get(f"{url}/agents/a-2")
        assert status == 200
        assert body["parent_uuid"] == "a-1"
        _get(f"{url}/agents/nope")
        raise AssertionError("expected 404")
    except urllib.error.HTTPError as exc:
        assert exc.code == 404


def test_api_read_only(server):
    outer = server[1]
    status, body = outer.handle("POST", "/agents", b"{}")
    assert status == 405
