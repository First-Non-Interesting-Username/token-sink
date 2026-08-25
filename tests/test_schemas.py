"""Tests for the schemas/ directory (issue #9, PLAN §11).

Every schema must:
- be valid JSON Schema draft 2020-12,
- resolve its relative $ref pointers against common.schema.json,
- accept a minimal valid example instance,
- reject instances missing required fields or carrying invalid enum values.
"""

import json
from pathlib import Path

import pytest
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012

from jsonschema import Draft202012Validator

SCHEMAS_DIR = Path(__file__).resolve().parent.parent / "schemas"

# All 16 record types required by PLAN §11 (+ common defs).
EXPECTED_SCHEMAS = {
    "campaign",
    "scope_policy",
    "agent",
    "task",
    "provider",
    "model",
    "router_decision",
    "search_result",
    "extracted_source",
    "evidence_item",
    "finding",
    "review",
    "poc",
    "final_report",
    "usage_event",
    "audit_event",
}

UUID = "123e4567-e89b-42d3-a456-426614174000"
TS = "2026-08-25T12:00:00Z"


def _envelope(**extra):
    """Minimal versioned_record envelope shared by all examples."""
    base = {
        "uuid": UUID,
        "schema_version": 1,
        "created_at": TS,
        "updated_at": TS,
        "version": 1,
    }
    base.update(extra)
    return base


def _load(name):
    # accept both "campaign" and "campaign.schema" as stem forms
    path = SCHEMAS_DIR / f"{name.removesuffix('.schema')}.schema.json"
    return json.loads(path.read_text())


def _registry():
    registry = Registry()
    for path in SCHEMAS_DIR.glob("*.schema.json"):
        contents = _load(path.stem)
        resource = Resource.from_contents(contents, default_specification=DRAFT202012)
        # register under the file name AND the schema's own $id so relative
        # refs like "common.schema.json#/..." resolve from either base
        registry = registry.with_resource(f"{path.name}", resource)
        if "$id" in contents:
            registry = registry.with_resource(contents["$id"], resource)
    return registry


@pytest.fixture(scope="module")
def registry():
    return _registry()


def test_all_plan11_schemas_present():
    found = {p.stem.replace(".schema", "") for p in SCHEMAS_DIR.glob("*.schema.json")}
    missing = EXPECTED_SCHEMAS - found
    assert not missing, f"missing schemas: {missing}"


@pytest.mark.parametrize("name", sorted(EXPECTED_SCHEMAS))
def test_schema_is_valid_draft202012(name):
    schema = _load(name)
    Draft202012Validator.check_schema(schema)


# --- example instances -------------------------------------------------------

EXAMPLES = {
    "campaign": _envelope(
        name="Hack Club Security recon",
        authorization_reference="HCS-2026-001",
        in_scope=["example.com"],
        out_of_scope=["mail.example.com"],
        prohibited_actions=["denial_of_service"],
        active_testing_enabled=False,
    ),
    "scope_policy": _envelope(campaign_uuid=UUID, in_scope_targets=["example.com"]),
    "agent": _envelope(campaign_uuid=UUID, role="discovery", status="created"),
    "task": _envelope(campaign_uuid=UUID, status="pending", description="scan example.com"),
    "provider": _envelope(
        name="gateway-x",
        provider_class="partly_free_gateway",
        auth_status="authenticated",
        trust_level="approved_non_sensitive_only",
    ),
    "model": _envelope(provider_uuid=UUID, identifier="m-1", free_status="unknown"),
    "router_decision": _envelope(
        task_uuid=UUID,
        candidate_plan={"selected_model_uuid": UUID, "rationale": "lowest latency", "confidence": 0.9},
    ),
    "search_result": _envelope(
        campaign_uuid=UUID,
        query="example.com vulnerability",
        scope_filter_result={"passed": True},
    ),
    "extracted_source": _envelope(
        campaign_uuid=UUID,
        source_url="https://example.com/",
        raw_content_hash="deadbeef",
        untrusted_input_label="untrusted_extracted_content",
    ),
    "evidence_item": _envelope(
        campaign_uuid=UUID,
        content_hash="cafebabe",
        epistemic_label="source_fact",
    ),
    "finding": _envelope(
        campaign_uuid=UUID,
        agent_uuid=UUID,
        state="initial_findings",
        state_transition_reason="created by discovery agent",
        content_hash="abc123",
    ),
    "review": _envelope(
        finding_uuid=UUID,
        reviewer_agent_uuid=UUID,
        review_kind="first_review",
        conclusion="confirmed",
    ),
    "poc": _envelope(
        finding_uuid=UUID,
        created_by_agent_uuid=UUID,
        target_kind="local_fixture",
        safety_notes="non-destructive GET only",
    ),
    "final_report": _envelope(finding_uuid=UUID, polished_by_agent_uuid=UUID),
    "usage_event": _envelope(
        campaign_uuid=UUID,
        agent_uuid=UUID,
        provider_name="gateway-x",
        model_identifier="m-1",
        free_tier_call=True,
    ),
    "audit_event": _envelope(
        event_kind="state_change",
        subject_record_type="finding",
        subject_record_uuid=UUID,
        event_hash="hash1",
    ),
}


@pytest.mark.parametrize("name", sorted(EXPECTED_SCHEMAS))
def test_example_instance_validates(name, registry):
    schema = _load(name)
    validator = Draft202012Validator(schema, registry=registry)
    errors = list(validator.iter_errors(EXAMPLES[name]))
    assert not errors, [e.message for e in errors]


@pytest.mark.parametrize(
    "name, mutation",
    [
        ("campaign", {"name": ""}),  # empty name rejected (minLength)
        ("campaign", {"prohibited_actions": ["be_nice"]}),  # invalid enum
        ("agent", {"status": "teleported"}),  # invalid status enum
        ("model", {"free_status": "probably_free"}),  # unknown free-status must be explicit
        ("finding", {"content_hash": None}),  # content hash is required
        ("review", {"conclusion": "vibes"}),  # invalid conclusion
        ("extracted_source", {"untrusted_input_label": "trusted"}),  # const mismatch
        ("audit_event", None),  # envelope-only instance lacks required event fields
    ],
)
def test_invalid_instances_rejected(name, mutation, registry):
    instance = dict(EXAMPLES[name])
    if mutation is not None:
        instance.update(mutation)
    else:
        # None means: strip everything beyond the versioned_record envelope
        for key in list(instance):
            if key not in {"uuid", "schema_version", "created_at", "updated_at", "version"}:
                del instance[key]
    validator = Draft202012Validator(_load(name), registry=registry)
    assert list(validator.iter_errors(instance)), f"{name}: expected rejection"


def test_finding_requires_state_transition_reason(registry):
    # §10/§11: state changes must carry an explicit reason — no silent edits.
    instance = dict(EXAMPLES["finding"])
    del instance["state_transition_reason"]
    validator = Draft202012Validator(_load("finding"), registry=registry)
    assert any("state_transition_reason" in e.message for e in validator.iter_errors(instance))


def test_common_defs_resolve_across_schemas(registry):
    # A bad UUID anywhere must be caught through the cross-file $ref.
    # format "uuid" is annotation-only in draft 2020-12, so enable the checker.
    from jsonschema import FormatChecker
    instance = dict(EXAMPLES["agent"])
    instance["uuid"] = "not-a-uuid"
    validator = Draft202012Validator(_load("agent"), registry=registry, format_checker=FormatChecker())
    assert list(validator.iter_errors(instance))
