"""Deletion & quarantine safeguard tests (issue #48, PLAN §10.2/§10.5)."""

from __future__ import annotations

import pytest

from findings.lifecycle import (
    FindingLifecycle,
    LifecycleError,
    RecordStore,
    State,
)

AGENT = "11111111-1111-1111-1111-111111111111"
REVIEWER = "22222222-2222-2222-2222-222222222222"
DISPUTER = "33333333-3333-3333-3333-333333333333"
THIRD = "44444444-4444-4444-4444-444444444444"
CAMPAIGN = "55555555-5555-5555-5555-555555555555"


@pytest.fixture()
def lc():
    return FindingLifecycle(RecordStore())


def make_finding(lc):
    return lc.submit_finding(
        CAMPAIGN, AGENT, {"title": "SQLi in login", "category": "injection"}
    ).finding


def claim(lc, finding, who=REVIEWER):
    lc.claim_for_review(finding.finding_uuid, who, "2099-01-01T00:00:00+00:00")


class TestSingleRejectionNoDelete:
    def test_single_incorrect_never_deletes(self, lc):
        f = make_finding(lc)
        claim(lc, f)
        lc.record_first_review(f.finding_uuid, REVIEWER, "incorrect")
        assert f.state == State.REVIEW_CYCLE_1  # held pending dispute, NOT deleted

    def test_dispute_support_advances_instead_of_delete(self, lc):
        f = make_finding(lc)
        claim(lc, f)
        lc.record_first_review(f.finding_uuid, REVIEWER, "incorrect")
        res = lc.resolve_dispute(f.finding_uuid, DISPUTER, supports_finding=True)
        assert res.finding.state == State.VALIDATED_OR_DISPUTED


class TestReviewerIndependence:
    def test_same_reviewer_cannot_double_confirm(self, lc):
        f = make_finding(lc)
        claim(lc, f)
        lc.record_first_review(f.finding_uuid, REVIEWER, "incorrect")
        with pytest.raises(LifecycleError, match="independence"):
            lc.resolve_dispute(f.finding_uuid, REVIEWER, supports_finding=False)
        # Still not deleted after the rejected attempt.
        assert f.state == State.REVIEW_CYCLE_1

    def test_distinct_reviewer_satisfies_dual_confirmation(self, lc):
        f = make_finding(lc)
        claim(lc, f)
        lc.record_first_review(f.finding_uuid, REVIEWER, "incorrect")
        res = lc.resolve_dispute(f.finding_uuid, DISPUTER, supports_finding=False)
        assert res.finding.state == State.DELETED


class TestTombstone:
    def test_tombstone_preserves_history(self, lc):
        f = make_finding(lc)
        claim(lc, f)
        lc.record_first_review(f.finding_uuid, REVIEWER, "incorrect")
        res = lc.resolve_dispute(f.finding_uuid, DISPUTER, supports_finding=False)
        history = res.transitions
        assert len(history) >= 2
        reasons = [t.reason for t in history]
        assert "dual_confirmation_deletion" in reasons
        # Every state transition carries a pre-transition content hash so
        # tampering with history is detectable (append-only, never removed).
        # The deletion transition itself pins the pre-deletion record hash.
        deletion = [t for t in history if t.reason == "dual_confirmation_deletion"]
        assert len(deletion) == 1
        assert deletion[0].payload.get("content_hash")
        assert deletion[0].payload.get("tombstone") is True

    def test_deleted_is_terminal(self, lc):
        f = make_finding(lc)
        claim(lc, f)
        lc.record_first_review(f.finding_uuid, REVIEWER, "incorrect")
        lc.resolve_dispute(f.finding_uuid, DISPUTER, supports_finding=False)
        with pytest.raises(LifecycleError):
            lc.resolve_dispute(f.finding_uuid, THIRD, supports_finding=False)


class TestQuarantineDeletion:
    def _quarantined(self, lc):
        f = make_finding(lc)
        claim(lc, f)
        lc.record_first_review(f.finding_uuid, REVIEWER, "confirmed")
        lc.advance(f.finding_uuid, REVIEWER)  # → impact_analysis
        lc.advance(f.finding_uuid, REVIEWER)  # → poc_draft
        lc.advance(f.finding_uuid, REVIEWER)  # → poc_review
        lc.record_poc_review(
            f.finding_uuid,
            reviewer_agent_uuid=REVIEWER,
            verdict="reject",
            blocking_safety_or_validity_objection=False,
        )
        lc.record_poc_review(f.finding_uuid, reviewer_agent_uuid=DISPUTER, verdict="reject")
        lc.record_poc_review(f.finding_uuid, reviewer_agent_uuid=THIRD, verdict="reject")
        lc.record_poc_review(f.finding_uuid, reviewer_agent_uuid=AGENT, verdict="reject")
        lc.evaluate_poc_quorum(f.finding_uuid, actor_uuid=REVIEWER)
        return f

    def test_quarantine_requires_dual_confirmation_to_delete(self, lc):
        f = self._quarantined(lc)
        assert f.state == State.QUARANTINED
        # A single confirmation can never delete.
        with pytest.raises(LifecycleError, match="distinct"):
            lc.delete_from_quarantine(f.finding_uuid, REVIEWER, REVIEWER)

    def test_quarantine_dual_confirmation_deletes_with_tombstone(self, lc):
        f = self._quarantined(lc)
        res = lc.delete_from_quarantine(f.finding_uuid, DISPUTER, THIRD)
        assert res.finding.state == State.DELETED
        reasons = [t.reason for t in res.transitions]
        assert "dual_confirmation_deletion_from_quarantine" in reasons
