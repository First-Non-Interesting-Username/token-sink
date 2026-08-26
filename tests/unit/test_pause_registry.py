"""Tests for scoped pause/resume semantics (issue #115)."""

import pytest

from orchestrator.pause_registry import PauseError, PauseRegistry, PauseScope


def test_agent_level_pause_blocks_only_that_agent():
    reg = PauseRegistry()
    reg.pause(PauseScope.AGENT, "a-1", actor="op")
    assert reg.is_paused(agent_id="a-1")
    assert not reg.is_paused(agent_id="a-2")
    assert not reg.is_paused(campaign_id="c-1")


def test_campaign_pause_blocks_its_agents():
    reg = PauseRegistry()
    reg.pause(PauseScope.CAMPAIGN, "c-1", actor="op", reason="quiesce before export")
    assert reg.is_paused(campaign_id="c-1")
    assert not reg.is_paused(campaign_id="c-2")


def test_global_pause_dominates():
    reg = PauseRegistry()
    reg.pause(PauseScope.GLOBAL, None, actor="op")
    assert reg.is_paused(campaign_id="c-1", agent_id="a-9")
    assert reg.blocking_pause(campaign_id="c-1", agent_id="a-9").scope is PauseScope.GLOBAL


def test_most_specific_pause_reported_for_ui():
    reg = PauseRegistry()
    reg.pause(PauseScope.CAMPAIGN, "c-1", actor="op")
    rec = reg.blocking_pause(campaign_id="c-1", agent_id=None)
    assert rec.scope is PauseScope.CAMPAIGN and rec.actor == "op"


def test_lift_and_double_lift():
    reg = PauseRegistry()
    reg.pause(PauseScope.AGENT, "a-1", actor="op")
    assert reg.lift(PauseScope.AGENT, "a-1")
    assert not reg.is_paused(agent_id="a-1")
    assert not reg.lift(PauseScope.AGENT, "a-1")


def test_scoped_pause_requires_target():
    with pytest.raises(PauseError):
        PauseRegistry().pause(PauseScope.AGENT, None, actor="op")


def test_ttl_expiry_lifts_pause_and_logs_for_audit():
    t = [1000.0]
    reg = PauseRegistry(now=lambda: t[0])
    reg.pause(PauseScope.GLOBAL, None, actor="op", ttl_seconds=60)
    assert reg.is_paused()
    t[0] = 1061.0
    assert not reg.is_paused()
    assert len(reg.expired_for_audit) == 1


def test_restart_while_paused_stays_paused():
    reg = PauseRegistry()
    reg.pause(PauseScope.CAMPAIGN, "c-7", actor="op", reason="maintenance")
    restored = PauseRegistry.from_json(reg.to_json())
    assert restored.is_paused(campaign_id="c-7"), "pause must survive restart (§12)"
    assert restored.blocking_pause(campaign_id="c-7").reason == "maintenance"


def test_active_pauses_listing_is_sorted_and_json_safe():
    reg = PauseRegistry()
    reg.pause(PauseScope.AGENT, "a-2", actor="op")
    reg.pause(PauseScope.GLOBAL, None, actor="admin")
    recs = reg.active_pauses()
    assert [r.scope for r in recs] == [PauseScope.AGENT, PauseScope.GLOBAL]
    import json

    json.dumps(reg.to_json())  # must not raise
