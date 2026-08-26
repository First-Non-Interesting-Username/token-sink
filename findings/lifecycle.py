"""Finding lifecycle state machine (PLAN §10).

Implements the finding workflow as a state machine over versioned records
with an append-only transition history. Storage-agnostic: the caller supplies
a `RecordStore` implementation; this module owns the transition rules, review
gates, and deletion safeguards.

States (PLAN §10):

    initial_findings → review_cycle_1 → validated_or_disputed
      → impact_analysis → poc_draft → poc_review → polished_report
      → final_review → vulnerabilities

Extra terminal/quasi-terminal states not in the linear flow:

    quarantined   — all four PoC reviewers rejected the finding
    deleted       — tombstone only; original record is never removed
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import TYPE_CHECKING, Any

from findings.review_policy import Phase

if TYPE_CHECKING:
    from findings.review_policy import ReviewPolicyEngine

from findings.deletion_guard import assert_not_deleted, require_distinct_reviewer


class LifecycleError(Exception):
    """Raised when an operation is invalid for the finding's current state."""


class State(StrEnum):
    INITIAL_FINDINGS = "initial_findings"
    REVIEW_CYCLE_1 = "review_cycle_1"
    VALIDATED_OR_DISPUTED = "validated_or_disputed"
    IMPACT_ANALYSIS = "impact_analysis"
    POC_DRAFT = "poc_draft"
    POC_REVIEW = "poc_review"
    POLISHED_REPORT = "polished_report"
    FINAL_REVIEW = "final_review"
    VULNERABILITIES = "vulnerabilities"
    QUARANTINED = "quarantined"
    DELETED = "deleted"


# The linear happy path from PLAN §10.
LINEAR_ORDER = [
    State.INITIAL_FINDINGS,
    State.REVIEW_CYCLE_1,
    State.VALIDATED_OR_DISPUTED,
    State.IMPACT_ANALYSIS,
    State.POC_DRAFT,
    State.POC_REVIEW,
    State.POLISHED_REPORT,
    State.FINAL_REVIEW,
    State.VULNERABILITIES,
]

# Allowed transitions. Kept explicit rather than derived from LINEAR_ORDER so
# exceptional edges (revert, quarantine) are visible in one place.
ALLOWED_TRANSITIONS: dict[State, list[State]] = {
    State.INITIAL_FINDINGS: [State.REVIEW_CYCLE_1],
    # A first review concluding "incorrect" can be disputed independently;
    # the disputed path is handled by ReviewGate logic below, so from
    # review_cycle_1 we either advance or stay pending dispute resolution.
    # review_cycle_1: advance, or tombstone via dual-confirmation deletion
    # (§10.2). DELETED is terminal.
    State.REVIEW_CYCLE_1: [
        State.VALIDATED_OR_DISPUTED,
        State.DELETED,
    ],
    State.VALIDATED_OR_DISPUTED: [State.IMPACT_ANALYSIS],
    State.IMPACT_ANALYSIS: [State.POC_DRAFT],
    State.POC_DRAFT: [State.POC_REVIEW],
    # All-four-reject may quarantine OR revert to post-first-review state
    # (PLAN §10.5). Otherwise advance to polished_report.
    State.POC_REVIEW: [
        State.POLISHED_REPORT,
        State.QUARANTINED,
        State.VALIDATED_OR_DISPUTED,  # revert target per §10.5
    ],
    State.POLISHED_REPORT: [State.FINAL_REVIEW],
    State.FINAL_REVIEW: [State.VULNERABILITIES],
    # Quarantine can be released back to post-first-review with new evidence,
    # or tombstoned via dual-confirmation deletion (§10.5, issue #48).
    State.QUARANTINED: [
        State.VALIDATED_OR_DISPUTED,
        State.DELETED,
    ],
    # Tombstones are terminal — nothing transitions out of deleted.
    State.DELETED: [],
}

# States in which a lease must currently be held to act on a finding.
LEASED_STATES = set(LINEAR_ORDER) - {
    State.INITIAL_FINDINGS,
    State.VULNERABILITIES,
}

REVIEW_CONCLUSIONS = {"confirmed", "likely", "inconclusive", "incorrect"}
POC_VERDICTS = {"accept", "reject"}


def _now() -> str:
    return datetime.now(UTC).isoformat()


def content_hash(record: dict[str, Any]) -> str:
    """Stable hash of a record dict (canonical JSON, sorted keys)."""
    return hashlib.sha256(
        json.dumps(record, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


@dataclass
class Lease:
    agent_uuid: str
    expires_at: str


@dataclass
class Finding:
    """A versioned finding record (PLAN §11 required fields included)."""

    schema_version: str
    finding_uuid: str
    campaign_uuid: str
    parent_finding_uuid: str | None
    title: str
    category: str
    affected_asset: str
    location: str
    observation: str
    hypothesis: str
    evidence_refs: list[str] = field(default_factory=list)
    repro_outline: list[str] = field(default_factory=list)
    suspected_impact: str = ""
    confidence: float = 0.0
    scope_policy_result: str = ""
    tool_provenance: dict[str, Any] = field(default_factory=dict)
    model_provider_metadata: dict[str, Any] = field(default_factory=dict)
    redaction_status: str = "unredacted"
    owner_agent_uuid: str | None = None
    lease: Lease | None = None
    state: State = State.INITIAL_FINDINGS
    reviews: list[dict[str, Any]] = field(default_factory=list)
    poc_reviews: list[dict[str, Any]] = field(default_factory=list)

    @classmethod
    def create(cls, campaign_uuid: str, title: str, **kwargs: Any) -> Finding:
        return cls(
            schema_version="1",
            finding_uuid=str(uuid.uuid4()),
            campaign_uuid=campaign_uuid,
            parent_finding_uuid=None,
            title=title,
            category=kwargs.pop("category", "unknown"),
            affected_asset=kwargs.pop("affected_asset", ""),
            location=kwargs.pop("location", ""),
            observation=kwargs.pop("observation", ""),
            hypothesis=kwargs.pop("hypothesis", ""),
            **kwargs,
        )

    def to_dict(self) -> dict[str, Any]:
        d = self.__dict__.copy()
        if self.lease is not None:
            d["lease"] = vars(self.lease)
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Finding:
        f = cls.__new__(cls)
        f.__dict__.update(d)
        if isinstance(f.lease, dict):
            f.lease = Lease(**f.lease)
        return f


@dataclass
class Transition:
    """One entry of the append-only transition history."""

    seq: int
    finding_uuid: str
    from_state: str
    to_state: str
    reason: str
    actor_uuid: str
    timestamp: str
    payload: dict[str, Any] = field(default_factory=dict)


@dataclass
class LifecycleResult:
    """Outcome of a transition: the new current record plus its history."""

    finding: Finding
    version: int
    transitions: list[Transition]


class RecordStore:
    """Minimal storage interface. Implementations persist versions +
    append-only history atomically (PLAN §12); this base class is in-memory
    and used by tests."""

    def __init__(self) -> None:
        self._versions: dict[str, list[Finding]] = {}
        self._history: dict[str, list[Transition]] = {}

    def load(self, finding_uuid: str) -> Finding | None:
        versions = self._versions.get(finding_uuid)
        return versions[-1] if versions else None

    def save(self, finding: Finding, transition: Transition) -> None:
        self._versions.setdefault(finding.finding_uuid, []).append(finding)
        self._history.setdefault(finding.finding_uuid, []).append(transition)

    def history(self, finding_uuid: str) -> list[Transition]:
        return list(self._history.get(finding_uuid, []))


class FindingLifecycle:
    """Enforces the §10 state machine against a RecordStore."""

    def __init__(self, store: RecordStore) -> None:
        self.store = store

    # -- helpers ---------------------------------------------------------

    def _record(
        self,
        finding: Finding,
        from_state: State,
        to_state: State,
        reason: str,
        actor_uuid: str,
        payload: dict[str, Any] | None = None,
    ) -> LifecycleResult:
        if to_state not in ALLOWED_TRANSITIONS.get(from_state, []):
            raise LifecycleError(f"illegal transition {from_state.value} -> {to_state.value}")
        # Mutate the record only after the transition is validated.
        finding.state = to_state
        prev = finding.to_dict()
        prev["state"] = from_state.value
        # Snapshot the pre-transition record hash into the audit entry so any
        # later tampering is detectable without trusting the stored version.
        transition = Transition(
            seq=len(self.store.history(finding.finding_uuid)),
            finding_uuid=finding.finding_uuid,
            from_state=from_state.value,
            to_state=to_state.value,
            reason=reason,
            actor_uuid=actor_uuid,
            timestamp=_now(),
            payload={"content_hash": content_hash(prev), **(payload or {})},
        )
        finding.parent_finding_uuid = (
            finding.parent_finding_uuid  # keep original lineage
        )
        self.store.save(finding, transition)
        return LifecycleResult(
            finding=finding,
            version=len(self.store.history(finding.finding_uuid)),
            transitions=self.store.history(finding.finding_uuid),
        )

    def _require_lease(self, finding: Finding, agent_uuid: str) -> None:
        if finding.state in LEASED_STATES:
            if finding.lease is None or finding.lease.agent_uuid != agent_uuid:
                raise LifecycleError("valid lease required for this operation")

    # -- lifecycle operations ---------------------------------------------

    def submit_finding(
        self, campaign_uuid: str, discovering_agent_uuid: str, fields: dict[str, Any]
    ) -> LifecycleResult:
        """§10.1 initial discovery."""
        finding = Finding.create(campaign_uuid=campaign_uuid, **fields)
        finding.owner_agent_uuid = discovering_agent_uuid
        # New findings enter the review queue immediately (§10.2: reviewers
        # claim from the queue of initial findings).
        finding.state = State.REVIEW_CYCLE_1
        transition = Transition(
            seq=0,
            finding_uuid=finding.finding_uuid,
            from_state="",
            to_state=State.INITIAL_FINDINGS.value,
            reason="discovered",
            actor_uuid=discovering_agent_uuid,
            timestamp=_now(),
        )
        self.store.save(finding, transition)
        # Second entry records the move into the first review cycle so the
        # append-only history shows both steps.
        t2 = Transition(
            seq=1,
            finding_uuid=finding.finding_uuid,
            from_state=State.INITIAL_FINDINGS.value,
            to_state=State.REVIEW_CYCLE_1.value,
            reason="queued_for_first_review",
            actor_uuid=discovering_agent_uuid,
            timestamp=_now(),
        )
        self.store.save(finding, t2)
        return LifecycleResult(
            finding=finding,
            version=2,
            transitions=self.store.history(finding.finding_uuid),
        )

    def claim_for_review(
        self, finding_uuid: str, reviewer_agent_uuid: str, lease_expires_at: str
    ) -> Finding:
        """§10.2 lease-based claiming for the first review cycle."""
        finding = self._get(finding_uuid)
        if finding.state != State.REVIEW_CYCLE_1:
            raise LifecycleError(
                f"claiming requires state {State.REVIEW_CYCLE_1.value}, got {finding.state.value}"
            )
        if finding.lease is not None:
            raise LifecycleError("finding already leased")
        finding.lease = Lease(agent_uuid=reviewer_agent_uuid, expires_at=lease_expires_at)
        self._append_history_only(finding, "lease_acquired", reviewer_agent_uuid)
        return finding

    def record_first_review(
        self,
        finding_uuid: str,
        reviewer_agent_uuid: str,
        conclusion: str,
        notes: str = "",
    ) -> LifecycleResult:
        """§10.2 first review cycle.

        confirmed/likely/inconclusive → advance to validated_or_disputed with
        dissent attached. incorrect → stays put until an independent dispute
        review resolves it (see resolve_dispute).
        """
        if conclusion not in REVIEW_CONCLUSIONS:
            raise LifecycleError(f"invalid conclusion {conclusion!r}")
        finding = self._get(finding_uuid)
        self._require_lease(finding, reviewer_agent_uuid)
        finding.reviews.append(
            {
                "cycle": 1,
                "reviewer": reviewer_agent_uuid,
                "conclusion": conclusion,
                "notes": notes,
                "timestamp": _now(),
            }
        )
        if conclusion == "incorrect":
            # Hold in place; dispute review decides deletion vs advancement.
            self._append_history_only(
                finding, "first_review_incorrect_pending_dispute", reviewer_agent_uuid
            )
            return LifecycleResult(
                finding=finding,
                version=len(self.store.history(finding_uuid)),
                transitions=self.store.history(finding_uuid),
            )
        return self._transition(
            finding,
            State.VALIDATED_OR_DISPUTED,
            reason=f"first_review_{conclusion}",
            actor_uuid=reviewer_agent_uuid,
        )

    def resolve_dispute(
        self,
        finding_uuid: str,
        dispute_reviewer_uuid: str,
        supports_finding: bool,
        notes: str = "",
    ) -> LifecycleResult | None:
        """§10.2 dual-confirmation deletion rule.

        Returns a tombstone result when both reviewers say incorrect; returns
        a normal advancement when at least one supports the finding (dissent
        attached). Never silently removes anything.
        """
        finding = self._get(finding_uuid)
        assert_not_deleted(finding)
        if finding.state != State.REVIEW_CYCLE_1:
            raise LifecycleError("no dispute open outside review_cycle_1")
        first_incorrect = any(r.get("conclusion") == "incorrect" for r in finding.reviews)
        if not first_incorrect:
            raise LifecycleError("no 'incorrect' first-review conclusion on record")
        # §10.2 independence: the dispute reviewer must be a distinct agent
        # from every prior reviewer — an agent can never double-confirm its
        # own 'incorrect' verdict into a deletion.
        require_distinct_reviewer(finding, dispute_reviewer_uuid)
        finding.reviews.append(
            {
                "cycle": 1,
                "kind": "independent_dispute",
                "reviewer": dispute_reviewer_uuid,
                "supports_finding": supports_finding,
                "notes": notes,
                "timestamp": _now(),
            }
        )
        if supports_finding:
            # Advance with all dissenting opinions attached (they live in
            # finding.reviews).
            return self._transition(
                finding,
                State.VALIDATED_OR_DISPUTED,
                reason="dispute_overruled_advanced_with_dissent",
                actor_uuid=dispute_reviewer_uuid,
            )
        # Both concluded incorrect → dual confirmation satisfied. Tombstone:
        # keep every prior version + audit entry, mark record deleted.
        return self._transition(
            finding,
            State.DELETED,
            reason="dual_confirmation_deletion",
            actor_uuid=dispute_reviewer_uuid,
            payload={"tombstone": True},
        )

    def advance(self, finding_uuid: str, actor_uuid: str) -> LifecycleResult:
        """Advance one step along the linear §10 pipeline.

        Gated on the finding having passed first review — initial_findings
        and review_cycle_1 must move through record_first_review, not this
        generic stepper (stricter behavior favors the safety posture).
        """
        finding = self._get(finding_uuid)
        if finding.state in (
            State.INITIAL_FINDINGS,
            State.REVIEW_CYCLE_1,
        ):
            raise LifecycleError(
                "advance() requires a post-first-review state; use "
                "record_first_review() to leave the review queue"
            )
        idx = LINEAR_ORDER.index(finding.state)
        nxt = LINEAR_ORDER[idx + 1]
        return self._transition(finding, nxt, reason="advanced", actor_uuid=actor_uuid)

    def record_poc_review(
        self,
        finding_uuid: str,
        reviewer_agent_uuid: str,
        verdict: str,
        blocking_safety_or_validity_objection: bool = False,
        reproduction_quality: str = "",
        missing_evidence: str = "",
        requested_changes: str = "",
        confidence: float = 0.0,
        saw_prior_reviews: bool = False,
        policy_engine: ReviewPolicyEngine | None = None,
    ) -> LifecycleResult:
        """§10.5 four-agent PoC review — one reviewer's verdict.

        When a ``policy_engine`` is supplied (review-mode configuration,
        PLAN §10.5), visibility is enforced *before* the review is
        recorded: in independent-first mode a reviewer who saw prior
        results before blind collection completed is rejected so the
        violation never enters the record.
        """
        if verdict not in POC_VERDICTS:
            raise LifecycleError(f"invalid verdict {verdict!r}")
        finding = self._get(finding_uuid)
        if finding.state != State.POC_REVIEW:
            raise LifecycleError("PoC reviews only accepted during poc_review")
        if policy_engine is not None:
            # Enforce mode rules pre-record; raises on independent-first violations.
            policy_engine.check_visibility(
                Phase.POC_REVIEW,
                finding.poc_reviews,
                saw_prior_reviews=saw_prior_reviews,
            )
        # Discussion-first mode allows seeing prior results; independent-first
        # forbids it until blind collection completes. Mode selection lives in
        # campaign policy; we record what the reviewer saw for auditability.
        finding.poc_reviews.append(
            {
                "reviewer": reviewer_agent_uuid,
                "verdict": verdict,
                "blocking_safety_or_validity_objection": blocking_safety_or_validity_objection,
                "reproduction_quality": reproduction_quality,
                "missing_evidence": missing_evidence,
                "requested_changes": requested_changes,
                "confidence": confidence,
                "saw_prior_reviews": saw_prior_reviews,
                "timestamp": _now(),
            }
        )
        self._append_history_only(finding, "poc_review_recorded", reviewer_agent_uuid)
        return LifecycleResult(
            finding=finding,
            version=len(self.store.history(finding_uuid)),
            transitions=self.store.history(finding_uuid),
        )

    def evaluate_poc_quorum(
        self,
        finding_uuid: str,
        actor_uuid: str,
        require_all_accept: bool = False,
        policy_engine: ReviewPolicyEngine | None = None,
    ) -> LifecycleResult | None:
        """§10.5 quorum evaluation once four reviews are in.

        Default policy: all four accept, OR quorum accepts with no blocking
        safety/validity objection. If require_all_accept, only unanimous
        acceptance advances. All-reject → quarantine (caller may instead use
        revert_from_poc_review for the post-first-review revert path).

        When ``policy_engine`` is supplied (review-mode configuration), its
        quorum policy decides; the legacy ``require_all_accept`` flag is a
        shorthand for the same knob and applies only without an engine.
        """
        finding = self._get(finding_uuid)
        if finding.state != State.POC_REVIEW:
            raise LifecycleError("quorum evaluated only during poc_review")
        reviews = finding.poc_reviews

        if policy_engine is not None:
            decision = policy_engine.evaluate(Phase.POC_REVIEW, reviews)
            return self._apply_quorum_decision(finding, decision, actor_uuid)

        if len(reviews) < 4:
            raise LifecycleError(f"need 4 PoC reviews, have {len(reviews)}")
        verdicts = [r["verdict"] for r in reviews]
        blocking = any(r["blocking_safety_or_validity_objection"] for r in reviews)
        accepts = sum(v == "accept" for v in verdicts)

        if all(v == "accept" for v in verdicts):
            return self._transition(
                finding,
                State.POLISHED_REPORT,
                reason="poc_quorum_all_accept",
                actor_uuid=actor_uuid,
            )
        if not require_all_accept and accepts >= 3 and not blocking:
            return self._transition(
                finding,
                State.POLISHED_REPORT,
                reason="poc_quorum_majority_no_block",
                actor_uuid=actor_uuid,
            )
        if all(v == "reject" for v in verdicts):
            return self._transition(
                finding,
                State.QUARANTINED,
                reason="poc_all_reject_quarantined",
                actor_uuid=actor_uuid,
            )
        # Mixed outcome with no quorum → no transition; more evidence needed.
        self._append_history_only(finding, "poc_quorum_unresolved", actor_uuid)
        return None

    def revert_from_poc_review(
        self, finding_uuid: str, actor_uuid: str, reason: str
    ) -> LifecycleResult:
        """§10.5 alternative to quarantine on all-reject: revert to
        post-first-review state for additional evidence."""
        finding = self._get(finding_uuid)
        if finding.state != State.POC_REVIEW:
            raise LifecycleError("revert only valid from poc_review")
        rejects = sum(1 for r in finding.poc_reviews if r["verdict"] == "reject")
        if len(finding.poc_reviews) >= 4 and rejects < 4:
            raise LifecycleError(
                "revert-to-post-first-review requires all four reviewers to reject"
            )
        return self._transition(
            finding,
            State.VALIDATED_OR_DISPUTED,
            reason=f"all_reject_revert: {reason}",
            actor_uuid=actor_uuid,
        )

    def delete_from_quarantine(
        self,
        finding_uuid: str,
        first_reviewer_uuid: str,
        second_reviewer_uuid: str,
        notes: str = "",
    ) -> LifecycleResult:
        """§10.5: quarantined findings follow the same dual-confirmation rule.

        Permanent deletion of a quarantined finding requires two distinct
        reviewers both concluding it is incorrect; the tombstone path is the
        same as §10.2 (history preserved, never silently removed).
        """
        finding = self._get(finding_uuid)
        assert_not_deleted(finding)
        if finding.state != State.QUARANTINED:
            raise LifecycleError("delete_from_quarantine requires state=quarantined")
        if first_reviewer_uuid == second_reviewer_uuid:
            raise LifecycleError("dual confirmation requires two distinct reviewers")
        require_distinct_reviewer(finding, first_reviewer_uuid)
        require_distinct_reviewer(finding, second_reviewer_uuid)
        finding.reviews.append(
            {
                "kind": "quarantine_deletion_confirmation_1",
                "reviewer": first_reviewer_uuid,
                "conclusion": "incorrect",
                "notes": notes,
                "timestamp": _now(),
            }
        )
        finding.reviews.append(
            {
                "kind": "quarantine_deletion_confirmation_2",
                "reviewer": second_reviewer_uuid,
                "conclusion": "incorrect",
                "notes": notes,
                "timestamp": _now(),
            }
        )
        return self._transition(
            finding,
            State.DELETED,
            reason="dual_confirmation_deletion_from_quarantine",
            actor_uuid=second_reviewer_uuid,
            payload={"tombstone": True},
        )

    def release_quarantine(self, finding_uuid: str, actor_uuid: str) -> LifecycleResult:
        """New evidence arrived; resume from post-first-review state."""
        finding = self._get(finding_uuid)
        assert_not_deleted(finding)
        return self._transition(
            finding,
            State.VALIDATED_OR_DISPUTED,
            reason="quarantine_released_new_evidence",
            actor_uuid=actor_uuid,
        )

    def finalize_report(self, finding_uuid: str, actor_uuid: str) -> LifecycleResult:
        """§10.6 write final report into vulnerabilities/<finding-id>/.

        Only callable after final_review passed (state already VULNERABILITIES
        via advance()). Submission remains a separate human-approved action —
        out of scope here by design.
        """
        finding = self._get(finding_uuid)
        if finding.state != State.VULNERABILITIES:
            raise LifecycleError("final report requires final_review to have passed")
        self._append_history_only(finding, "final_report_written", actor_uuid)
        return LifecycleResult(
            finding=finding,
            version=len(self.store.history(finding_uuid)),
            transitions=self.store.history(finding_uuid),
        )

    # -- internal ----------------------------------------------------------

    def _apply_quorum_decision(
        self, finding: Finding, decision: dict[str, Any] | None, actor_uuid: str
    ) -> LifecycleResult | None:
        """Map a ReviewPolicyEngine decision onto lifecycle transitions."""
        if decision is None:
            return None
        outcome = decision.get("outcome")
        if outcome == "advance":
            return self._transition(
                finding,
                State.POLISHED_REPORT,
                reason=f"poc_quorum_{decision.get('reason', 'advance')}",
                actor_uuid=actor_uuid,
            )
        if outcome == "reject_all":
            return self._transition(
                finding,
                State.QUARANTINED,
                reason="poc_all_reject_quarantined",
                actor_uuid=actor_uuid,
            )
        # pending / unresolved → no transition; more evidence needed.
        self._append_history_only(finding, f"poc_quorum_{outcome}", actor_uuid)
        return None

    def _get(self, finding_uuid: str) -> Finding:
        finding = self.store.load(finding_uuid)
        if finding is None:
            raise LifecycleError(f"unknown finding {finding_uuid}")
        # Stored records serialize the enum; hydrate defensively.
        if isinstance(finding.state, str):
            finding.state = State(finding.state)
        return finding

    def _transition(
        self,
        finding: Finding,
        to_state: State,
        reason: str,
        actor_uuid: str,
        payload: dict[str, Any] | None = None,
    ) -> LifecycleResult:
        from_state = State(finding.state)
        finding.lease = None  # leases don't survive transitions
        result = self._record(finding, from_state, to_state, reason, actor_uuid, payload)
        return result

    def _append_history_only(self, finding: Finding, event: str, actor_uuid: str) -> None:
        state = str(finding.state)
        t = Transition(
            seq=len(self.store.history(finding.finding_uuid)),
            finding_uuid=finding.finding_uuid,
            from_state=state,
            to_state=state,
            reason=event,
            actor_uuid=actor_uuid,
            timestamp=_now(),
        )
        self.store.save(finding, t)
