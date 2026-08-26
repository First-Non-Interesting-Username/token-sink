"""Tests for the Hack Club Security report format (issue #123).

Covers: finding→report mapping, completeness validation per gate (sections,
CWE shape, claim traceability, PoC checklist, redaction), specific failure
messages, dry-run reporting, and Markdown/JSON exports. Verifies no network
submission path exists.
"""

from __future__ import annotations

import json

import pytest

from findings.hackclub_report import (
    REQUIRED_SECTIONS,
    TEMPLATE_VERSION,
    ReportValidator,
    dry_run,
    export_json,
    export_markdown,
    map_finding_to_report,
)


def valid_report() -> dict:
    return {
        "template_version": TEMPLATE_VERSION,
        "title": "Reflected XSS in search",
        "affected_asset": "https://example.com/search",
        "vulnerability_class": "CWE-79",
        "severity_assessment": {
            "severity": "high",
            "rationale": "Session theft via injected script in attacker-controlled query param.",
        },
        "reproduction_steps": [
            "Navigate to /search?q=<svg onload=alert(1)>",
            "Observe script execution in page context",
        ],
        "poc_reference": "artifacts/ab/cd/deadbeef",
        "impact_analysis": "Attacker can hijack victim sessions.",
        "remediation_suggestion": "HTML-encode query output; add CSP.",
        "evidence_links": ["ev-1", "ev-2"],
        "claims": [],
        "poc_checklist": [{"item": "deterministic repro", "satisfied": True}],
    }


# --- mapping -------------------------------------------------------------------


def test_map_finding_to_report_covers_all_sections():
    finding = {
        "title": "t",
        "affected_asset": "a",
        "cwe": "CWE-22",
        "severity": "medium",
        "severity_rationale": "r",
        "repro_outline": ["s1"],
        "poc_ref": "p",
        "impact_analysis": "i",
        "remediation": "fix",
        "evidence_refs": ["e1"],
    }
    report = map_finding_to_report(finding)
    for section in REQUIRED_SECTIONS:
        assert section in report
    assert report["vulnerability_class"] == "CWE-22"
    assert report["reproduction_steps"] == ["s1"]


def test_mapped_empty_fields_are_placeholders_not_dropped():
    report = map_finding_to_report({"title": "only title"})
    assert report["vulnerability_class"] == ""
    validator = ReportValidator()
    gr = validator.validate(report)
    assert not gr.eligible
    assert any("vulnerability_class" in f.message for f in gr.failures)


# --- sections gate ---------------------------------------------------------------


def test_valid_report_is_eligible():
    gr = ReportValidator().validate(valid_report())
    assert gr.eligible, gr.summary()


@pytest.mark.parametrize(
    "section",
    [
        "title",
        "affected_asset",
        "reproduction_steps",
        "poc_reference",
        "impact_analysis",
        "remediation_suggestion",
        "evidence_links",
    ],
)
def test_each_missing_section_blocks_with_specific_message(section):
    report = valid_report()
    report[section] = "" if isinstance(report[section], str) else []
    gr = ReportValidator().validate(report)
    assert not gr.eligible
    assert any(f.gate == "sections" and section in f.message for f in gr.failures)


def test_severity_rationales_required():
    report = valid_report()
    report["severity_assessment"]["rationale"] = "  "
    failures = ReportValidator().validate(report).failures
    assert any("rationale" in f.message for f in failures)


# --- cwe gate ---------------------------------------------------------------------


def test_non_cwe_class_rejected():
    report = valid_report()
    report["vulnerability_class"] = "cross-site scripting"
    failures = ReportValidator().validate(report).failures
    assert any(f.gate == "cwe" for f in failures)
    assert ReportValidator().validate({**valid_report(), "vulnerability_class": "CWE-89"}).eligible


# --- traceability gate ---------------------------------------------------------------


class FakeEvidenceStore:
    """Duck-typed EvidenceStore returning canned traceability results."""

    def __init__(self, violations):
        self._violations = violations

    def check_traceability(self, claims):
        from findings.evidence import TraceabilityReport

        return TraceabilityReport(
            traceable=(), labeled_analysis=(), violations=tuple(self._violations)
        )


def test_untraceable_claims_block_with_reasons():
    report = valid_report()
    report["claims"] = [{"claim": "server runs nginx"}]
    validator = ReportValidator(FakeEvidenceStore(["server runs nginx: no evidence cited"]))
    failures = validator.validate(report).failures
    assert any(f.gate == "traceability" and "no evidence cited" in f.message for f in failures)


def test_traceable_claims_pass():
    report = valid_report()
    report["claims"] = [{"claim": "payload reflected", "evidence_uuids": ["ev-1"]}]
    validator = ReportValidator(FakeEvidenceStore([]))
    assert validator.validate(report).eligible


# --- poc checklist gate -------------------------------------------------------------


def test_unsatisfied_poc_checklist_items_block():
    report = valid_report()
    report["poc_checklist"] = [
        {"item": "deterministic repro", "satisfied": True},
        {"item": "runs offline against fixture", "satisfied": False},
    ]
    failures = ReportValidator().validate(report).failures
    assert any(f.gate == "poc_checklist" and "runs offline" in f.message for f in failures)


# --- redaction gate --------------------------------------------------------------------


@pytest.mark.parametrize(
    "secret", ["sk-projabcdefghij1234567890", "ghp_" + "a" * 36, "AKIAIOSFODNN7EXAMPLE"]
)
def test_embedded_secrets_block_export(secret):
    report = valid_report()
    report["impact_analysis"] = f"token was {secret} in logs"
    failures = ReportValidator().validate(report).failures
    assert any(f.gate == "redaction" for f in failures)
    # The failure message must not echo the secret back.
    redaction_failures = [f for f in failures if f.gate == "redaction"]
    assert all(secret not in f.message for f in redaction_failures)


def test_password_assignment_pattern_blocks():
    report = valid_report()
    report["remediation_suggestion"] = "rotate password: hunter2 immediately"
    assert any(f.gate == "redaction" for f in ReportValidator().validate(report).failures)


# --- dry-run + exports ------------------------------------------------------------------


def test_dry_run_reports_all_blocking_gates():
    report = map_finding_to_report({})  # everything empty
    gr = dry_run(report, ReportValidator())
    gates = {f.gate for f in gr.failures}
    assert "sections" in gates
    summary = gr.summary()
    assert "blocked by" in summary
    assert not gr.eligible


def test_markdown_export_renders_sections():
    md = export_markdown(valid_report())
    assert "# Reflected XSS in search" in md
    assert "CWE-79" in md
    assert "## Reproduction steps" in md
    assert "1. Navigate to" in md
    assert "`ev-1`" in md


def test_json_export_is_stable_and_roundtrippable():
    a = export_json(valid_report())
    b = export_json(json.loads(a))
    assert a == b  # byte-reproducible
    assert json.loads(a)["vulnerability_class"] == "CWE-79"


def test_no_network_submission_code_path():
    """§15: the agent never submits — the module must contain no network calls."""
    import inspect

    import findings.hackclub_report as mod

    src = inspect.getsource(mod)
    forbidden = (
        "requests.",
        "urllib",
        "http.client",
        "socket.",
        "httpx",
        "curl",
        "post(",
        "fetch(",
    )
    assert not any(tok in src for tok in forbidden)
