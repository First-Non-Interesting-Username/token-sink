"""Tests for cli/campaign_wizard.py (issue #171, PLAN §5)."""

import pytest

from cli.campaign_wizard import (
    WizardError,
    build_manifest,
    run_wizard,
    validate_campaign_draft,
)
from schemas.validate import SchemaRegistry

REGISTRY = SchemaRegistry()

VALID_DRAFT = {
    "name": "acme-q3-web-assessment",
    "authorization_reference": "ACME-RT-2026-014",
    "program_name": "ACME public bug bounty",
    "in_scope": ["api.example.com", "https://app.example.com/login"],
    "out_of_scope": ["internal.example.com"],
    "allowed_methods": ["GET", "POST"],
    "prohibited_actions": ["dos", "social_engineering"],
    "active_testing_enabled": True,
    "allowed_test_classes": ["vulnerability_scanning"],
    "max_request_rate_per_target": 60,
}


# -- validation --------------------------------------------------------------


def test_valid_draft_has_no_errors():
    assert validate_campaign_draft(VALID_DRAFT) == []


def test_missing_required_fields():
    errors = validate_campaign_draft({})
    assert any("name" in e for e in errors)
    assert any("authorization_reference" in e for e in errors)
    assert any("in_scope" in e for e in errors)


def test_placeholder_name_rejected():
    d = dict(VALID_DRAFT, name="test")
    assert any("placeholder" in e for e in validate_campaign_draft(d))


def test_empty_out_of_scope_rejected():
    d = dict(VALID_DRAFT, out_of_scope=[])
    errs = validate_campaign_draft(d)
    assert any("out_of_scope must not be empty" in e for e in errs)


def test_in_out_overlap_detected():
    d = dict(VALID_DRAFT, out_of_scope=["api.example.com"])
    errs = validate_campaign_draft(d)
    assert any("overlap" in e for e in errs)


def test_invalid_cidr_target_rejected():
    d = dict(VALID_DRAFT, in_scope=["10.0.0.0/99"])
    errs = validate_campaign_draft(d)
    assert any("invalid target" in e for e in errs)


def test_unknown_http_method_rejected():
    d = dict(VALID_DRAFT, allowed_methods=["BREW"])
    assert any("unknown HTTP methods" in e for e in validate_campaign_draft(d))


def test_unknown_test_class_rejected():
    d = dict(VALID_DRAFT, allowed_test_classes=["teleportation"])
    assert any("unknown test classes" in e for e in validate_campaign_draft(d))


def test_active_without_test_class_rejected():
    d = dict(VALID_DRAFT, allowed_test_classes=[])
    errs = validate_campaign_draft(d)
    assert any("requires at least one allowed_test_class" in e for e in errs)


def test_test_classes_without_active_flag_rejected():
    d = dict(VALID_DRAFT, active_testing_enabled=False)
    errs = validate_campaign_draft(d)
    assert any("active_testing_enabled is false" in e for e in errs)


@pytest.mark.parametrize(
    "field", ["max_request_rate_per_target", "token_budget", "max_concurrency_per_target"]
)
def test_nonpositive_limits_rejected(field):
    d = dict(VALID_DRAFT, **{field: 0})
    assert any(f"{field} must be a positive number" in e for e in validate_campaign_draft(d))
    d2 = dict(VALID_DRAFT, **{field: -5})
    assert any(f"{field} must be a positive number" in e for e in validate_campaign_draft(d2))


# -- manifest ----------------------------------------------------------------


def test_manifest_matches_schema():
    manifest = build_manifest(VALID_DRAFT)
    result = REGISTRY.validate("campaign", manifest)
    assert result.valid, result.errors


def test_invalid_draft_cannot_be_saved():
    bad = dict(VALID_DRAFT, out_of_scope=[])
    with pytest.raises(WizardError):
        build_manifest(bad)


def test_manifest_carries_scope_verbatim():
    manifest = build_manifest(VALID_DRAFT)
    assert [t["identifier"] for t in manifest["in_scope_targets"]] == [
        "api.example.com",
        "https://app.example.com/login",
    ]
    assert manifest["out_of_scope_targets"] == [
        {"kind": "domain", "identifier": "internal.example.com"}
    ]
    assert manifest["record_type"] == "campaign"
    assert manifest["campaign_uuid"]


# -- interactive wizard ------------------------------------------------------


def _answers(*responses):
    return iter(responses)


def test_wizard_happy_path(monkeypatch):
    answers = _answers(
        "acme-q3-web-assessment",
        "ACME-RT-2026-014",
        "api.example.com, app.example.com",
        "internal.example.com",
        "y",
        "vulnerability_scanning",
    )
    monkeypatch.setattr("builtins.input", lambda prompt="": next(answers))
    manifest = run_wizard()
    assert manifest["name"] == "acme-q3-web-assessment"
    assert manifest["active_testing_enabled"] is True


def test_wizard_retries_bad_name_then_accepts(monkeypatch):
    answers = _answers(
        "",  # empty → keeps nothing → error loop
        "test",  # placeholder → rejected
        "real-campaign-name",
        "AUTH-REF-1",
        "scope.example.com",
        "excluded.example.com",
        "N",
    )
    monkeypatch.setattr("builtins.input", lambda prompt="": next(answers))
    manifest = run_wizard()
    assert manifest["name"] == "real-campaign-name"


def test_wizard_passive_campaign_no_out_scope_fails(monkeypatch):
    # Even passive campaigns require an explicit exclusion list.
    answers = _answers(
        "some-name",
        "AUTH-REF-1",
        "scope.example.com",
        "",
    )
    monkeypatch.setattr("builtins.input", lambda prompt="": next(answers))
    with pytest.raises((StopIteration, WizardError)):
        run_wizard()
