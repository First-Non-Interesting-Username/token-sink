"""Schema round-trip tests for every entity in spec §11."""
from __future__ import annotations

from datetime import UTC

import pytest

from mavr.schemas import entities as s


def _now_iso() -> str:
    from datetime import datetime

    return datetime.now(UTC).isoformat()


def _campaign() -> dict:
    return {
        "id": "11111111-1111-4111-8111-111111111111",
        "name": "t",
        "target_spec": {"hosts": ["example.com"]},
        "state": "draft",
    }


def _scope() -> dict:
    return {
        "id": "22222222-2222-4222-8222-222222222222",
        "campaign_id": "11111111-1111-4111-8111-111111111111",
        "allowed_targets": ["example.com"],
        "allowed_methods": ["GET"],
    }


def _provider() -> dict:
    return {
        "id": "33333333-3333-4333-8333-333333333333",
        "provider_id": "test",
        "display_name": "Test",
        "kind": "native",
        "free": True,
        "free_status": "confirmed",
    }


def _model(provider_id: str) -> dict:
    return {
        "id": "44444444-4444-4444-8444-444444444444",
        "provider_id": provider_id,
        "model_key": "test-model",
        "display_name": "Test",
        "free": True,
        "free_status": "confirmed",
    }


def test_campaign_round_trip() -> None:
    out = s.round_trip(s.Campaign, _campaign())
    assert isinstance(out, s.Campaign)


def test_scope_policy_round_trip() -> None:
    out = s.round_trip(s.ScopePolicy, _scope())
    assert out.allowed_methods == ["GET"]


def test_agent_round_trip() -> None:
    payload = {
        "id": "55555555-5555-4555-8555-555555555555",
        "role": "discovery",
        "status": "created",
        "campaign_id": "11111111-1111-4111-8111-111111111111",
    }
    out = s.round_trip(s.Agent, payload)
    assert out.role == s.AgentRole.DISCOVERY


def test_task_round_trip() -> None:
    payload = {
        "id": "66666666-6666-4666-8666-666666666666",
        "campaign_id": "11111111-1111-4111-8111-111111111111",
        "kind": "search",
    }
    out = s.round_trip(s.Task, payload)
    assert out.kind == s.TaskKind.SEARCH


def test_provider_round_trip() -> None:
    out = s.round_trip(s.Provider, _provider())
    assert out.kind == s.ProviderKind.NATIVE


def test_model_round_trip() -> None:
    out = s.round_trip(s.Model, _model("33333333-3333-4333-8333-333333333333"))
    assert out.free_status == s.FreeStatus.CONFIRMED


def test_router_decision_round_trip() -> None:
    payload = {
        "id": "77777777-7777-4777-8777-777777777777",
        "task_id": "66666666-6666-4666-8666-666666666666",
        "router_id": "r1",
        "candidates": [{"model_key": "x", "score": 0.9}],
        "confidence": 0.8,
    }
    out = s.round_trip(s.RouterDecision, payload)
    assert out.confidence == 0.8


def test_search_result_round_trip() -> None:
    payload = {
        "id": "88888888-8888-4888-8888-888888888888",
        "campaign_id": "11111111-1111-4111-8111-111111111111",
        "query": "x",
        "engine": "ddgs",
        "rank": 1,
        "url": "https://example.com/",
    }
    out = s.round_trip(s.SearchResult, payload)
    assert out.engine == "ddgs"


def test_extracted_source_round_trip() -> None:
    payload = {
        "id": "99999999-9999-4999-8999-999999999999",
        "campaign_id": "11111111-1111-4111-8111-111111111111",
        "source_url": "https://example.com/",
        "final_url": "https://example.com/",
        "content_type": "text/html",
        "byte_length": 100,
        "content_hash": "a" * 64,
        "raw_artifact_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        "extractor": "curl",
    }
    out = s.round_trip(s.ExtractedSource, payload)
    assert out.extractor == "curl"


def test_evidence_item_round_trip() -> None:
    payload = {
        "id": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
        "campaign_id": "11111111-1111-4111-8111-111111111111",
        "source_url": "https://example.com/",
        "content_hash": "a" * 64,
        "byte_length": 100,
        "content_type": "text/html",
        "raw_artifact_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
    }
    out = s.round_trip(s.EvidenceItem, payload)
    assert out.content_hash == "a" * 64


def test_finding_round_trip_and_state() -> None:
    payload = {
        "id": "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
        "campaign_id": "11111111-1111-4111-8111-111111111111",
        "title": "XSS in search box",
        "state": "initial_findings",
        "severity": "high",
    }
    out = s.round_trip(s.Finding, payload)
    assert out.state == s.FindingState.INITIAL
    assert out.severity == s.Severity.HIGH


@pytest.mark.parametrize("state", list(s.FindingState))
def test_all_finding_states_round_trip(state: s.FindingState) -> None:
    payload = {
        "id": "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
        "campaign_id": "11111111-1111-4111-8111-111111111111",
        "title": "t",
        "state": state.value,
    }
    out = s.round_trip(s.Finding, payload)
    assert out.state == state


def test_review_round_trip() -> None:
    payload = {
        "id": "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
        "finding_id": "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
        "version": 1,
        "reviewer_agent_id": "55555555-5555-4555-8555-555555555555",
        "verdict": "accept",
        "validity": "valid",
        "reproduction_quality": "high",
        "scope_safety": "safe",
        "severity_consistency": "consistent",
        "confidence": 0.9,
    }
    out = s.round_trip(s.Review, payload)
    assert out.verdict == s.ReviewVerdict.ACCEPT


def test_poc_round_trip() -> None:
    payload = {
        "id": "ffffffff-ffff-4fff-8fff-ffffffffffff",
        "finding_id": "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
        "version": 1,
        "setup": "start docker",
        "commands": ["curl http://localhost:8080"],
        "target_kind": "local_mock",
    }
    out = s.round_trip(s.PoC, payload)
    assert out.target_kind == "local_mock"


def test_final_report_round_trip() -> None:
    payload = {
        "id": "12121212-1212-4121-8121-121212121212",
        "finding_id": "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
        "version": 1,
        "report_path": "/tmp/r.md",
        "evidence_manifest_path": "/tmp/ev.json",
        "redaction_manifest_path": "/tmp/red.json",
        "hash_manifest": "f" * 64,
    }
    out = s.round_trip(s.FinalReport, payload)
    assert out.hash_manifest == "f" * 64


def test_usage_event_rejects_paid_with_free() -> None:
    import pydantic

    payload = {
        "id": "13131313-1313-4131-8131-131313131313",
        "event_id": "evt-1",
        "provider_id": "p",
        "model_key": "m",
        "is_free": True,
        "is_paid": True,
    }
    with pytest.raises(pydantic.ValidationError):
        s.UsageEvent.model_validate(payload)


def test_audit_event_round_trip() -> None:
    payload = {
        "id": "14141414-1414-4141-8141-141414141414",
        "event_id": "evt-1",
        "actor_kind": "agent",
        "category": "state_transition",
        "actor_id": "55555555-5555-4555-8555-555555555555",
    }
    out = s.round_trip(s.AuditEvent, payload)
    assert out.category == s.AuditCategory.STATE_TRANSITION


def test_schema_version_present_on_every_entity() -> None:
    """Every schema has a ``schema_version`` field set to the package value."""
    instances: list[s.BaseModel] = [
        s.Campaign(**_campaign()),
        s.ScopePolicy(**_scope()),
        s.Agent(
            id="55555555-5555-4555-8555-555555555555",
            role=s.AgentRole.DISCOVERY,
        ),
        s.Task(
            id="66666666-6666-4666-8666-666666666666",
            campaign_id="11111111-1111-4111-8111-111111111111",
            kind=s.TaskKind.SEARCH,
        ),
        s.Provider(**_provider()),
        s.Model(**_model("33333333-3333-4333-8333-333333333333")),
        s.RouterDecision(
            id="77777777-7777-4777-8777-777777777777",
            task_id="66666666-6666-4666-8666-666666666666",
            router_id="r1",
        ),
        s.SearchResult(
            id="88888888-8888-4888-8888-888888888888",
            campaign_id="11111111-1111-4111-8111-111111111111",
            query="q",
            engine="ddgs",
            rank=1,
            url="https://example.com/",
        ),
        s.EvidenceItem(
            id="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
            campaign_id="11111111-1111-4111-8111-111111111111",
            source_url="https://example.com/",
            content_hash="a" * 64,
            byte_length=1,
            content_type="text/html",
            raw_artifact_id="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        ),
        s.Finding(
            id="cccccccc-cccc-4ccc-8ccc-cccccccccccc",
            campaign_id="11111111-1111-4111-8111-111111111111",
            title="x",
        ),
        s.Review(
            id="eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
            finding_id="cccccccc-cccc-4ccc-8ccc-cccccccccccc",
            version=1,
            reviewer_agent_id="55555555-5555-4555-8555-555555555555",
            verdict=s.ReviewVerdict.ACCEPT,
            validity="valid",
            reproduction_quality="high",
            scope_safety="safe",
            severity_consistency="consistent",
        ),
        s.PoC(
            id="ffffffff-ffff-4fff-8fff-ffffffffffff",
            finding_id="cccccccc-cccc-4ccc-8ccc-cccccccccccc",
            version=1,
            setup="s",
            commands=["c"],
            target_kind="local_mock",
        ),
        s.FinalReport(
            id="12121212-1212-4121-8121-121212121212",
            finding_id="cccccccc-cccc-4ccc-8ccc-cccccccccccc",
            version=1,
            report_path="/r.md",
            evidence_manifest_path="/e.json",
            redaction_manifest_path="/d.json",
            hash_manifest="f" * 64,
        ),
        s.UsageEvent(
            id="13131313-1313-4131-8131-131313131313",
            event_id="evt-1",
            provider_id="p",
            model_key="m",
        ),
        s.AuditEvent(
            id="14141414-1414-4141-8141-141414141414",
            event_id="evt-1",
            actor_kind=s.ActorKind.SYSTEM,
            category=s.AuditCategory.CONFIG,
        ),
    ]
    for inst in instances:
        assert inst.schema_version == s.SCHEMA_VERSION
