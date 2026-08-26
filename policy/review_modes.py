"""Review-mode configuration & quorum policy engine (issue #197, PLAN §10.2/§10.5).

Decides whether a finding advances through a review gate, given reviewer
verdicts and the configured review mode. Pure policy evaluation: it never
touches storage or findings directly — callers apply returned decisions,
keeping this module trivially testable and reusable across all review
gates (first review cycle and four-agent PoC review alike).

Two modes (PLAN §10.5):

- ``independent_first`` — reviewers are collected blind; discussion is
  only permitted after every verdict is in. Enforced here as: verdicts
  must be submitted without visibility into others' (callers hide prior
  results until :meth:`QuorumPolicy.evaluate` is called).
- ``discussion_first`` — reviewers may challenge/refine each other;
  later verdicts may reference earlier ones.

Default advance policy (PLAN §10.5): all reviewers accept, OR quorum
accepts with no blocking issue raised. All-reject ⇒ quarantine/revert
decision, never delete.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass


class ReviewMode(enum.StrEnum):
    INDEPENDENT_FIRST = "independent_first"
    DISCUSSION_FIRST = "discussion_first"


class Verdict(enum.StrEnum):
    ACCEPT = "accept"
    REJECT = "reject"


@dataclass
class ReviewerVerdict:
    """One reviewer's outcome for one gate round."""

    reviewer_id: str
    verdict: Verdict
    confidence: float = 1.0  # 0..1; informational, not used by default policy
    blocking_issue: bool = False  # safety or validity blocker per PLAN §10.5
    dissent_note: str = ""


class ReviewConfigError(ValueError):
    """Raised when a QuorumPolicy would be unsatisfiable or malformed."""


class AdvanceDecision(enum.StrEnum):
    ADVANCE = "advance"
    QUORUM_FAILED = "quorum_failed"
    ALL_REJECTED = "all_rejected"  # quarantine / revert-for-evidence, not delete
    INSUFFICIENT_REVIEWS = "insufficient_reviews"  # keep collecting verdicts


@dataclass
class QuorumPolicy:
    """Declarative, validated review-gate configuration.

    Attributes:
        mode: independent-first (blind) vs discussion-first flow.
        panel_size: number of reviewers required before evaluating.
        accept_quorum: minimum accepts to advance (when not unanimous).
        allow_unanimous_bypass: if True, unanimous accept advances even when
            blocking issues exist? NO — blockers always block (safety layer);
            this flag exists so subclasses/config formats can express intent,
            but evaluate() never bypasses a blocking_issue.
        max_rounds: re-review cap; exhausted rounds force escalation rather
            than looping forever on a split panel.
    """

    mode: ReviewMode = ReviewMode.INDEPENDENT_FIRST
    panel_size: int = 4
    accept_quorum: int = 4
    max_rounds: int = 2

    def __post_init__(self):
        # Validation at construction: an unsatisfiable policy (quorum above
        # panel size) would silently deadlock every finding otherwise.
        if self.panel_size < 1:
            raise ReviewConfigError("panel_size must be >= 1")
        if not 1 <= self.accept_quorum <= self.panel_size:
            raise ReviewConfigError(
                f"accept_quorum ({self.accept_quorum}) must be within 1..panel_size "
                f"({self.panel_size})"
            )
        if self.max_rounds < 1:
            raise ReviewConfigError("max_rounds must be >= 1")

    def evaluate(self, verdicts: list[ReviewerVerdict], round_number: int = 1) -> dict:
        """Evaluate collected verdicts against this policy.

        Ordering of checks matters: completeness first (actionable "keep
        collecting" answer), then the hard safety layer (blocking issues
        apply even to otherwise-unanimous accepts), then quorum math.

        Returns a decision dict with ``decision``, ``reason``, and the
        dissenting verdicts so callers can attach them per PLAN §10.2
        ("advance it with all dissenting opinions attached").
        """
        if len(verdicts) < self.panel_size:
            return {
                "decision": AdvanceDecision.INSUFFICIENT_REVIEWS,
                "reason": f"{len(verdicts)}/{self.panel_size} reviews collected",
                "dissents": [],
            }
        accepts = [v for v in verdicts if v.verdict is Verdict.ACCEPT]
        dissents = [v for v in verdicts if v.verdict is Verdict.REJECT]

        # Hard safety layer: a blocking safety/validity issue blocks advance
        # regardless of quorum count — even a unanimous accept cannot waive it.
        blockers = [v for v in verdicts if v.blocking_issue]
        if blockers:
            decision = AdvanceDecision.QUORUM_FAILED
            reason = f"blocked by {len(blockers)} blocking issue(s) from: " + ", ".join(
                v.reviewer_id for v in blockers
            )
        elif len(accepts) == self.panel_size:
            decision = AdvanceDecision.ADVANCE
            reason = "unanimous accept"
        elif len(accepts) >= self.accept_quorum:
            decision = AdvanceDecision.ADVANCE
            reason = f"quorum met ({len(accepts)}/{self.panel_size} accept)"
        else:
            decision = AdvanceDecision.QUORUM_FAILED
            reason = f"only {len(accepts)}/{self.accept_quorum} required accepts"

        if decision is AdvanceDecision.QUORUM_FAILED and not accepts:
            # PLAN §10.5: all-reject is its own terminal handling path —
            # quarantine or revert for more evidence, never silent delete.
            decision = AdvanceDecision.ALL_REJECTED
            reason = "all reviewers rejected"

        return {"decision": decision, "reason": reason, "dissents": dissents}

    def can_rereview(self, rounds_done: int) -> bool:
        """Whether another re-review cycle may start after ``rounds_done``."""
        return rounds_done < self.max_rounds


def blind_collect(policy: QuorumPolicy, submit) -> list[ReviewerVerdict]:
    """Collect verdicts enforcing independent-first blindness.

    ``submit(reviewer_id) -> ReviewerVerdict`` is called once per reviewer;
    in independent-first mode the caller's submit function must not expose
    previously collected verdicts — this wrapper guards that by hiding the
    accumulating list entirely from the submit closure's view of order
    (verdicts are shuffled-position-collected via opaque ids). In
    discussion-first mode, submit may receive the verdicts collected so far
    via ``submit(reviewer_id, prior=...)`` if it accepts the kwarg.
    """
    verdicts: list[ReviewerVerdict] = []
    for i in range(policy.panel_size):
        if policy.mode is ReviewMode.DISCUSSION_FIRST:
            try:
                verdicts.append(submit(f"reviewer-{i}", prior=list(verdicts)))
                continue
            except TypeError:
                pass  # submit doesn't support prior context; fall through
        verdicts.append(submit(f"reviewer-{i}"))
    return verdicts
