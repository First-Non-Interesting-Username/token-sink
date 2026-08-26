"""Unit tests for the claim-to-evidence traceability gate (issue #282).

Includes deliberately untraceable-claim fixtures that MUST be caught, per
the issue's evaluation-fixture requirement.
"""

from __future__ import annotations

import pytest

from findings.claims import (
    CLAIM_KIND_ANALYSIS,
    Claim,
    TraceabilityError,
    check_traceability,
    render_chain,
)

EV = {"ev-1", "ev-2", "ev-3"}


def _claim(**overrides) -> Claim:
    base = {
        "text": "The login endpoint accepts weak passwords.",
        "kind": "evidence",
        "evidence_refs": ["ev-1"],
    }
    base.update(overrides)
    return Claim(**base)


# -- gate passes ----------------------------------------------------------------


def test_fully_traced_claims_pass() -> None:
    claims = [
        _claim(),
        _claim(evidence_refs=["ev-1", "ev-2"]),
        _claim(kind="analysis", text="Likely exploitable in chain with CSRF.", evidence_refs=[]),
    ]
    passing = check_traceability(claims, EV)
    assert len(passing) == 3


def test_analysis_label_alone_is_sufficient() -> None:
    claim = Claim(text="This likely generalizes to all v2 endpoints.", kind=CLAIM_KIND_ANALYSIS)
    assert check_traceability([claim], EV) == ["claim[0]"]


# -- untraceable fixtures that must be caught --------------------------------------

UNTRACEABLE_FIXTURES = [
    # No refs, evidence kind — the classic hallucinated claim.
    _claim(evidence_refs=[]),
    # Dangling ref: points at an artifact the finding doesn't have.
    _claim(evidence_refs=["ev-missing"]),
    # Empty text.
    _claim(text="  "),
]


@pytest.mark.parametrize("bad_claim", UNTRACEABLE_FIXTURES, ids=["no-ref", "dangling", "empty"])
def test_untraceable_claims_fail_the_gate(bad_claim: Claim) -> None:
    with pytest.raises(TraceabilityError):
        check_traceability([_claim(), bad_claim], EV)


def test_gate_error_names_every_offending_claim() -> None:
    with pytest.raises(TraceabilityError) as exc:
        check_traceability(UNTRACEABLE_FIXTURES[:2], EV)
    msg = str(exc.value)
    assert "claim[0]" in msg and "claim[1]" in msg
    assert "untraceable" in msg or "unknown evidence" in msg


def test_no_registry_means_refs_accepted_as_declared() -> None:
    claim = _claim(evidence_refs=["anything"])
    check_traceability([claim])  # no registry: structural check only


# -- invalid kinds -------------------------------------------------------------------


def test_invalid_kind_rejected() -> None:
    with pytest.raises(ValueError):
        Claim(text="x", kind="speculation")


# -- render view -----------------------------------------------------------------------


def test_render_chain_shows_claim_to_evidence_links() -> None:
    claims = [
        _claim(evidence_refs=["ev-1", "ev-2"]),
        Claim(text="Probably also affects staging.", kind=CLAIM_KIND_ANALYSIS),
    ]
    out = render_chain(claims)
    assert "[0] CLAIM:" in out and "ev-1, ev-2" in out
    assert "[1] ANALYSIS:" in out
