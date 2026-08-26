"""Tests for the claim-level fact-drift gate (issue #97, PLAN §10.6)."""

from findings.fact_drift import (
    evaluate_gate,
    extract_claims,
    store_diff_for_audit,
)

VALIDATED = {
    "finding_uuid": "f-1",
    "title": "SQL injection in /api/users search parameter",
    "category": "sql_injection",
    "affected_asset": "/api/users",
    "location": "search GET parameter",
    "observation": "The endpoint returns rows for arbitrary input. CVSS base score is 7.5.",
    "hypothesis": "",
    "repro_outline": ["send ' OR 1=1 to the search parameter", "observe 3 extra rows returned"],
    "suspected_impact": "high",
    "confidence": 0.9,
}


def test_extract_claims_is_atomic():
    claims = extract_claims(VALIDATED)
    assert claims["title"].startswith("SQL injection")
    assert any(k.startswith("observation#") for k in claims)
    assert claims["repro_outline#1"] == "observe 3 extra rows returned"


def test_legitimate_paraphrase_passes():
    report = {
        "claims": [
            {"claim": "SQL injection affects the search GET parameter of /api/users"},
            {
                "claim": "Arbitrary input yields database rows; CVSS base score 7.5 applies.",
            },
            {"claim": "Sending ' OR 1=1 to search returns three additional rows."},
            {"claim": "Impact is rated high with 0.9 confidence."},
        ]
    }
    v = evaluate_gate(VALIDATED, report)
    assert v.passed, v.violations


def test_numeric_drift_caught():
    report = {
        "claims": [
            {"claim": VALIDATED["title"]},
            {"claim": "The endpoint returns rows for arbitrary input. CVSS base score is 9.8."},
            {"claim": VALIDATED["repro_outline"][0]},
            {"claim": VALIDATED["repro_outline"][1]},
            {"claim": "Impact high, confidence 0.9."},
        ]
    }
    v = evaluate_gate(VALIDATED, report)
    assert not v.passed
    assert any("7.5" in m or "numeric" in m.lower() or "dropped" in m.lower() for m in v.violations)


def test_dropped_claim_caught():
    report = {"claims": [{"claim": VALIDATED["title"]}]}
    v = evaluate_gate(VALIDATED, report)
    assert not v.passed
    assert v.dropped_claims, "dropped validated claims must be listed"


def test_added_claim_requires_evidence():
    report = {
        "claims": [
            {"claim": VALIDATED["title"]},
            {"claim": VALIDATED["observation"]},
            {"claim": VALIDATED["repro_outline"][0]},
            {"claim": VALIDATED["repro_outline"][1]},
            {"claim": VALIDATED["suspected_impact"]},
            {"claim": "Also affects the admin panel at /admin", "evidence_uuids": ["ev-123"]},
        ]
    }

    def lookup(uuids: list[str]) -> list[str]:
        return uuids if uuids == ["ev-123"] else []

    v = evaluate_gate(VALIDATED, report, evidence_store_lookup=lookup)
    assert v.passed, v.violations


def test_added_claim_with_unknown_evidence_blocked():
    report = {
        "claims": [
            {"claim": VALIDATED["title"]},
            {"claim": VALIDATED["observation"]},
            {"claim": VALIDATED["repro_outline"][0]},
            {"claim": VALIDATED["repro_outline"][1]},
            {"claim": VALIDATED["suspected_impact"]},
            {"claim": "Also affects the admin panel", "evidence_uuids": ["ev-gone"]},
        ]
    }
    v = evaluate_gate(VALIDATED, report, evidence_store_lookup=lambda u: [])
    assert not v.passed
    assert v.added_claims


def test_analysis_labeled_addition_allowed():
    report = {
        "claims": [
            {"claim": VALIDATED["title"]},
            {"claim": VALIDATED["observation"]},
            {"claim": VALIDATED["repro_outline"][0]},
            {"claim": VALIDATED["repro_outline"][1]},
            {"claim": VALIDATED["suspected_impact"]},
            {"claim": "We believe this chains into RCE", "label": "analysis"},
        ]
    }
    v = evaluate_gate(VALIDATED, report)
    assert v.passed, v.violations


def test_free_text_report_shape():
    text = (
        f"{VALIDATED['title']}. {VALIDATED['observation']} "
        f"{VALIDATED['repro_outline'][0]}. {VALIDATED['repro_outline'][1]}. "
        "Severity: high; confidence 0.9."
    )
    v = evaluate_gate(VALIDATED, {"report": text})
    assert v.passed, v.violations


def test_signoff_overrides_but_records():
    report = {"claims": [{"claim": "A completely different finding entirely"}]}
    v = evaluate_gate(VALIDATED, report, signed_off=True)
    assert v.passed
    assert all("human-signed-off" in m for m in v.violations)
    d = store_diff_for_audit(v, "f-1")
    assert d["finding_uuid"] == "f-1"
    assert d["passed"] is True
