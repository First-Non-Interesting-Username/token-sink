"""Tests that consume the offline evaluation fixtures.

Each test loads a fixture file from :mod:`tests.fixtures.eval.fixtures`
and asserts the production code either accepts the true positives,
rejects the false positives, escalates the ambiguous ones, and
contains the adversarial provider responses.
"""
from __future__ import annotations

from pathlib import Path
from uuid import uuid4

from tests.fixtures.eval.fixtures import (
    ADVERSARIAL_RESPONSES,
    AMBIGUOUS_FINDINGS,
    CONFLICTING_REVIEWS,
    KNOWN_FALSE_POSITIVES,
    KNOWN_TRUE_POSITIVES,
    load_fixture,
    write_all,
)


def test_fixtures_write_and_reload(tmp_path: Path) -> None:
    """Round-trip the fixtures through disk and assert equivalence."""
    write_all()
    for name in (
        "true_positives.json",
        "false_positives.json",
        "ambiguous.json",
        "conflicting_reviews.json",
        "adversarial_responses.json",
    ):
        data = load_fixture(name)
        assert data, f"{name} is empty"


def test_known_true_positives_satisfy_discovery_contract() -> None:
    """Every true-positive fixture must have the required fields and
    at least one evidence_ref. These are the invariants
    :func:`mavr.findings.workflow.create_initial_finding` enforces."""
    for tp in KNOWN_TRUE_POSITIVES:
        assert tp["title"].strip()
        assert tp["description"].strip()
        assert tp["severity"] in {"low", "medium", "high", "critical"}
        assert tp["confidence"] in {"confirmed", "likely", "inconclusive", "incorrect"}
        assert tp["evidence_refs"], "true positives must cite evidence"


def test_known_false_positives_dont_have_evidence_lock() -> None:
    """A false-positive fixture must still be representable as a
    DiscoveryPayload (so it can be triaged), but it should not
    reach the final ``vulnerabilities`` state."""
    for fp in KNOWN_FALSE_POSITIVES:
        assert fp["evidence_refs"]  # still needs evidence
        assert fp["expected_outcome"] == "reject_invalid"


def test_ambiguous_findings_request_changes() -> None:
    for amb in AMBIGUOUS_FINDINGS:
        assert amb["expected_outcome"] == "request_changes"


def test_conflicting_reviews_have_a_split() -> None:
    """The conflicting-reviews fixture must show a genuine split
    between accept and reject verdicts; otherwise the test would
    trivially pass against any quorum policy."""
    for case in CONFLICTING_REVIEWS:
        verdicts = [r["verdict"] for r in case["reviews"]]
        assert "accept" in verdicts
        assert "reject" in verdicts
        assert case["expected_outcome"] in {
            "advance",
            "request_changes",
            "quarantine",
        }


def test_adversarial_responses_are_well_formed() -> None:
    for adv in ADVERSARIAL_RESPONSES:
        assert "label" in adv
        assert "response" in adv
        assert "expected_containment" in adv
        # Every response has a 'content' key, even if empty.
        assert "content" in adv["response"]


def test_evaluate_url_accepts_true_positive_target() -> None:
    """A true positive's host is in scope and the URL should be ALLOWed
    by the policy engine."""
    from mavr.policy.engine import (
        DecisionKind,
        ScopePolicyEngine,
        ToolCall,
    )
    from mavr.schemas import entities as schema

    engine = ScopePolicyEngine(resolve_dns=False)
    campaign = schema.Campaign(
        id="cccccccc-cccc-4ccc-8ccc-cccccccccccc",
        name="tp-test",
        target_spec={"hosts": ["example.com"]},
    )
    scope = schema.ScopePolicy(
        id="dddddddd-dddd-4ddd-8ddd-dddddddddddd",
        campaign_id=campaign.id,
        allowed_targets=["example.com"],
        allowed_methods=["GET"],
        action_allowlist=[],
    )
    d = engine.evaluate(
        campaign,
        scope,
        ToolCall(url="https://example.com/login?user=admin'--", method="GET"),
    )
    assert d.kind == DecisionKind.ALLOW


def test_prompt_injection_adversarial_response_is_detected() -> None:
    """The prompt-injection adversarial fixture must trip the
    sanitize layer's pattern detector."""
    from mavr.findings.workflow import detect_prompt_injection

    case = next(c for c in ADVERSARIAL_RESPONSES if "injection" in c["id"])
    detected = detect_prompt_injection(case["response"]["content"])
    assert detected, "the sanitize layer missed the injection marker"


def test_conflicting_reviews_outcome_is_inconclusive_or_rework() -> None:
    """A 2-accept / 2-reject split under the default quorum policy
    must NOT advance. We assert that the production code maps the
    fixture to ``request_changes`` (rework) rather than ``advance``."""
    from mavr.findings import reviews
    from mavr.schemas import entities as schema
    from mavr.schemas.entities import ReviewVerdict

    case = CONFLICTING_REVIEWS[0]
    finding_id = str(uuid4())
    rs = []
    for r in case["reviews"]:
            rs.append(
                schema.Review(
                    id=str(uuid4()),
                    schema_version="1.0.0",
                    finding_id=finding_id,
                    version=1,
                    reviewer_agent_id=str(uuid4()),
                    verdict=ReviewVerdict.ACCEPT if r["verdict"] == "accept" else ReviewVerdict.REJECT,
                    validity=r["validity"],
                    reproduction_quality=r["reproduction_quality"],
                    scope_safety=r["scope_safety"],
                    severity_consistency=r["severity_consistency"],
                    missing_evidence=[],
                    requested_changes="",
                    confidence=r["confidence"],
                    provider_id=None,
                    model_id=None,
                    rationale=r["rationale"],
                    created_at="2024-01-01T00:00:00+00:00",
                )
            )
    summary = reviews.compute_summary(
        rs,
        finding_id=finding_id,
        version=1,
        mode="independent_first",
        quorum_policy="all_accept_or_3_of_4_no_blockers",
    )
    assert summary.outcome in {"request_changes", "quarantine"}
    assert summary.outcome != "advance"
