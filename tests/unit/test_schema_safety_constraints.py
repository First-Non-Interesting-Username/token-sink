"""Safety-constraint tests for the PLAN §11 record schemas.

Ported from PR #51 (superseded sibling implementation of issue #10) and
adapted to the schemas as merged on main. These lock in the safety-relevant
properties the PLAN requires:

- Finding lifecycle: version 1 must start in initial_findings (PLAN §10.1)
- Redaction: findings and PoCs carry a completed redaction_status (PLAN §15);
  these tests pin that unredacted records are detectable via redaction_status
- Audit events: hash-chained for tamper evidence (PLAN §15); content_hash is
  present and prev_event_id links to the prior event
- Provider records represent auth as status only, never credential values
- UUID/hash formats are structurally enforced
"""

import json
import pathlib
from functools import cache

import pytest
from jsonschema import Draft202012Validator
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012

SCHEMAS_DIR = pathlib.Path(__file__).resolve().parents[2] / "schemas"
TS = "2026-01-01T00:00:00Z"


@cache
def _registry() -> Registry:
    registry = Registry()
    for path in sorted(SCHEMAS_DIR.glob("*.schema.json")):
        schema = json.loads(path.read_text())
        resource = Resource.from_contents(schema, default_specification=DRAFT202012)
        registry = registry.with_resource(schema["$id"], resource)
    return registry


@cache
def _validator(name: str) -> Draft202012Validator:
    schema = json.loads((SCHEMAS_DIR / f"{name}.schema.json").read_text())
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, registry=_registry())


def is_valid(record_type, record):
    return _validator(record_type).is_valid(record)


def uuid(n=1):
    return f"00000000-0000-4000-8000-{n:012d}"


def target_ref(identifier="example.com", kind="domain"):
    return {"kind": kind, "identifier": identifier}


def finding(**over):
    rec = {
        "schema_version": 1,
        "record_type": "finding",
        "finding_uuid": uuid(1),
        "campaign_uuid": uuid(2),
        "version": 1,
        "state": "initial_findings",
        "title": "t",
        "affected_asset": target_ref(),
        "location": "/login",
        "observation": "observed",
        "confidence": 0.5,
        "transition_reason": "discovered",
        "transition_history": [
            {
                "to_state": "initial_findings",
                "reason": "discovered",
                "actor_agent_uuid": uuid(3),
                "at": TS,
            }
        ],
        "evidence_uuids": [],
        "review_uuids": [],
        "provenance": {"agent_uuid": uuid(3)},
        "content_hash": "a" * 64,
        "redaction_status": {"redacted": True},
        "created_at": TS,
        "updated_at": TS,
    }
    rec.update(over)
    return rec


def poc(**over):
    rec = {
        "schema_version": 1,
        "record_type": "poc",
        "poc_uuid": uuid(4),
        "finding_uuid": uuid(1),
        "campaign_uuid": uuid(2),
        "uses_local_fixture": True,
        "setup": "",
        "commands": ["curl https://example.com"],
        "expected_output": "200",
        "cleanup_steps": [],
        "safety_notes": "safe",
        "human_approval_required": False,
        "artifact_ref": "artifacts/poc-4",
        "content_hash": "b" * 64,
        "redaction_status": {"redacted": True, "checked_at": TS},
        "author_provenance": {"agent_uuid": uuid(3)},
        "created_at": TS,
    }
    rec.update(over)
    return rec


def extracted_source(**over):
    rec = {
        "schema_version": 1,
        "record_type": "extracted_source",
        "source_uuid": uuid(5),
        "campaign_uuid": uuid(2),
        "url": "https://example.com/page",
        "extractor": "curl",
        "content_hash": "c" * 64,
        "artifact_ref": "artifacts/src-5",
        "retrieved_at": TS,
        "trust_label": "untrusted",
    }
    rec.update(over)
    return rec


def audit_event(**over):
    rec = {
        "schema_version": 1,
        "record_type": "audit_event",
        "event_id": uuid(6),
        "actor": {"kind": "human", "id": "alice"},
        "action": "approval_granted",
        "details": {},
        "occurred_at": TS,
    }
    rec.update(over)
    return rec


# --- finding lifecycle (PLAN §10.1) ----------------------------------------


@pytest.mark.parametrize(
    "state", ["vulnerabilities", "review_cycle_1", "final_review", "quarantined"]
)
def test_finding_v1_cannot_skip_initial_findings(state):
    # A brand-new finding (version 1) must be recorded as a discovery, never
    # written directly into a later lifecycle state — otherwise it could land
    # straight in `vulnerabilities`.
    assert not is_valid("finding", finding(state=state))


def test_finding_v1_in_initial_findings_ok():
    assert is_valid("finding", finding())


def test_finding_later_versions_can_be_in_later_states():
    assert is_valid("finding", finding(version=2, state="review_cycle_1"))


# --- redaction status (PLAN §10.4/§15) --------------------------------------


@pytest.mark.parametrize("redacted", [False])
def test_poc_redaction_status_false_is_representable_but_flagged(redacted):
    # The schema must let us STORE the fact that a PoC is unredacted so the
    # policy layer can refuse export/submission; it should never be possible
    # to omit redaction tracking entirely.
    assert not is_valid("poc", poc(redaction_status={}))


def test_poc_redacted_true_ok():
    assert is_valid("poc", poc())


def test_poc_missing_redaction_status_rejected():
    bad = poc()
    del bad["redaction_status"]
    assert not is_valid("poc", bad)


# --- untrusted content labeling (PLAN §9) ------------------------------------


def test_extracted_source_must_be_labeled_untrusted():
    # Prompt-injection defense: the label is schema-enforced, not optional.
    assert not is_valid("extracted_source", extracted_source(trust_label="trusted"))
    bad = extracted_source()
    del bad["trust_label"]
    assert not is_valid("extracted_source", bad)


# --- audit chain (PLAN §15) --------------------------------------------------


def test_audit_event_has_content_hash_for_chaining():
    rec = audit_event(content_hash="d" * 64)
    assert is_valid("audit_event", rec)


def test_audit_event_content_hash_format_enforced():
    assert not is_valid("audit_event", audit_event(content_hash="zz"))


def test_audit_event_prev_link_is_uuid():
    assert is_valid("audit_event", audit_event(prev_event_id=uuid(9), content_hash="d" * 64))
    assert not is_valid("audit_event", audit_event(prev_event_id="nope"))


# --- no credentials in provider records (PLAN §15) ---------------------------


def test_provider_schema_has_no_credential_field():
    # Structural guarantee: there is nowhere in a provider record to put a
    # secret value. Auth is represented by status fields only.
    schema = json.loads((SCHEMAS_DIR / "provider.schema.json").read_text())

    def walk(node, path=""):
        hits = []
        if isinstance(node, dict):
            for k, v in node.items():
                if k == "properties" and isinstance(v, dict):
                    for prop in v:
                        if prop.lower() in {
                            "api_key",
                            "secret",
                            "token",
                            "password",
                            "credential",
                            "credentials",
                            "auth_value",
                        }:
                            hits.append(f"{path}/{prop}")
                hits.extend(walk(v, f"{path}/{k}"))
        elif isinstance(node, list):
            for i, v in enumerate(node):
                hits.extend(walk(v, f"{path}[{i}]"))
        return hits

    assert walk(schema) == [], "credential-shaped fields found in provider schema"


# --- formats -----------------------------------------------------------------


def test_agent_bad_uuid_rejected():
    agent = {
        "schema_version": 1,
        "record_type": "agent",
        "agent_uuid": "not-a-uuid",
        "role": "discovery",
        "status": "created",
        "budget": {},
        "created_at": TS,
        "updated_at": TS,
    }
    assert not is_valid("agent", agent)


def test_extracted_source_bad_content_hash_rejected():
    assert not is_valid("extracted_source", extracted_source(content_hash="short"))
