"""Tests for the PoC safety validator (issue #164)."""

from __future__ import annotations

import pytest

from evaluation.fixtures import adversarial_pocs
from findings.poc_validator import (
    DestructivePatterns,
    PoCSafetyValidator,
    json_target_url,
)
from policy.scope import ScopePolicy, TargetSpec


@pytest.fixture()
def scope() -> ScopePolicy:
    return ScopePolicy(
        campaign_uuid="00000000-0000-4000-8000-00000000ffff",
        in_scope=[TargetSpec(value="https://allowed.example.test/")],
        out_of_scope=[],
    )


def _codes(verdict) -> set[str]:
    return {c["code"] for c in verdict.checks}


def test_clean_fixture_poc_passes(scope):
    v = PoCSafetyValidator(scope).validate(adversarial_pocs.base())
    assert v.passed, v.to_dict()


def test_missing_sections_fail():
    v = PoCSafetyValidator().validate(adversarial_pocs.missing_sections())
    assert not v.passed
    codes = _codes(v)
    assert "missing_section:expected_output" in codes
    assert "missing_section:cleanup_steps" in codes


def test_out_of_scope_target_rejected(scope):
    v = PoCSafetyValidator(scope).validate(adversarial_pocs.out_of_scope_target())
    assert not v.passed
    assert "out_of_scope_target" in _codes(v)


def test_out_of_scope_without_any_policy_rejected():
    # No-scope mode: only loopback references are acceptable.
    v = PoCSafetyValidator(None).validate(adversarial_pocs.out_of_scope_target())
    assert not v.passed


def test_destructive_patterns_detected(scope):
    v = PoCSafetyValidator(scope).validate(adversarial_pocs.destructive_payload())
    assert not v.passed
    codes = _codes(v)
    assert any(c.startswith("destructive_pattern:drop_table") for c in codes)
    assert any(c.startswith("destructive_pattern:rm_rf_variant") for c in codes)


def test_destructive_denylist_is_configurable(scope):
    # A narrower denylist that doesn't know about DROP TABLE still catches
    # rm -rf; custom entries extend coverage.
    poc = adversarial_pocs.destructive_payload()
    narrow = PoCSafetyValidator(
        scope,
        destructive=DestructivePatterns(
            patterns=(("rm_rf_variant", r"\brm\s+(-[a-zA-Z]*[rf][a-zA-Z]*\s+)+"),),
        ),
    ).validate(poc)
    assert not narrow.passed
    assert "destructive_pattern:drop_table" not in _codes(narrow)


def test_secret_in_command_string_detected(scope):
    # Secrets hidden inside command strings, not just prose.
    v = PoCSafetyValidator(scope).validate(adversarial_pocs.secret_leak())
    assert not v.passed
    codes = _codes(v)
    assert "secret_detected:github_token" in codes
    assert "secret_detected:generic_api_key_param" in codes


def test_pii_detected(scope):
    v = PoCSafetyValidator(scope).validate(adversarial_pocs.pii_in_prose())
    assert not v.passed
    assert "pii_detected:email_address" in _codes(v)


def test_verdict_snippets_are_clipped(scope):
    v = PoCSafetyValidator(scope).validate(adversarial_pocs.secret_leak())
    for check in v.checks:
        assert len(check["detail"].get("snippet", "")) <= 60


def test_fixture_preference_nudge(scope):
    v = PoCSafetyValidator(scope).validate(adversarial_pocs.live_target_where_fixture_suffices())
    # A nudge, not a block: passes overall but carries the warning.
    assert v.passed
    assert "prefer_local_fixture" in _codes(v)


def test_credential_stuffing_pattern(scope):
    v = PoCSafetyValidator(scope).validate(adversarial_pocs.credential_stuffing_pattern())
    assert not v.passed
    assert "destructive_pattern:credential_stuffing" in _codes(v)


def test_extra_secret_patterns_extend_detection(scope):
    poc = adversarial_pocs.base()
    poc["setup"] = "use corp token CORP-ABCDEF123456"
    strict = PoCSafetyValidator(
        scope, extra_secret_patterns=(("corp_token", r"\bCORP-[A-Z]{6}\d{6}\b"),)
    )
    assert "secret_detected:corp_token" in _codes(strict.validate(poc))
    # default validator doesn't know it
    default = PoCSafetyValidator(scope)
    assert "secret_detected:corp_token" not in _codes(default.validate(poc))


def test_verdict_serializable_and_storable(scope):
    d = PoCSafetyValidator(scope).validate(adversarial_pocs.base()).to_dict()
    import json

    assert json.loads(json.dumps(d)) == d
    assert d["passed"] is True and isinstance(d["checks"], list)


def test_json_target_url_helper():
    assert json_target_url({"url": "https://x.test/a"}) == "https://x.test/a"
    assert json_target_url({"host": "x.test"}) == "https://x.test"
    assert json_target_url("https://plain.string/") == "https://plain.string/"
    assert json_target_url({}) == ""
