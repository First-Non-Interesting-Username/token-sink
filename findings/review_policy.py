"""Review-mode configuration & quorum policy engine (PLAN §10.2, §10.5).

Implements the two review modes from §10.5 across all review gates:

- **independent-first**: reviews must be *blind* — a reviewer may not see
  prior review results until blind collection completes for the phase;
  only after collection does discussion open.
- **discussion-first**: reviewers may see and challenge prior results at
  any time.

The engine is storage-agnostic: callers feed it the reviews already
recorded for a finding and ask two questions:

1. ``check_visibility`` — may this reviewer see prior results right now?
   (Enforced *before* recording, so an independent-first violation never
   enters the record.)
2. ``evaluate`` — has the configured quorum policy been satisfied for the
   phase?

Policies (per phase, with safe defaults):

- ``quorum``: minimum accepting reviews required.
- ``require_all_accept``: unanimous acceptance required (§10.5 default
  policy option "All four must accept").
- ``forbid_blocking_objections``: no reviewer may hold a blocking safety
  or validity issue (§10.5 "…and no reviewer identifies a blocking safety
  or validity issue"). Blocking objections always fail the gate when set.

Design decisions:

- The engine *proposes* outcomes; it does not mutate findings. Lifecycle
  transitions stay in ``findings/lifecycle.py``, which calls into this
  module — one place owns state, one owns policy.
- Unknown phases are rejected rather than defaulted so a typo in campaign
  policy cannot silently weaken a safety gate.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class ReviewPolicyError(Exception):
    """Raised for invalid policy configuration or malformed requests."""


class ReviewMode(StrEnum):
    INDEPENDENT_FIRST = "independent_first"
    DISCUSSION_FIRST = "discussion_first"


class Phase(StrEnum):
    FIRST_REVIEW = "first_review"
    DISPUTE_REVIEW = "dispute_review"
    POC_REVIEW = "poc_review"
    FINAL_REVIEW = "final_review"


# Phases that run as a multi-reviewer panel subject to quorum rules.
# first_review/dispute_review are single-reviewer gates (§10.2): they are
# visibility-governed but have no quorum to evaluate.
QUORUM_PHASES = {Phase.POC_REVIEW}


@dataclass(frozen=True)
class QuorumPolicy:
    """Quorum rules applied to a panel phase (default §10.5 policy)."""

    quorum: int = 3  # majority of four; §10.5 "a quorum accepts"
    require_all_accept: bool = False
    forbid_blocking_objections: bool = True

    def __post_init__(self) -> None:
        if self.quorum < 1:
            raise ReviewPolicyError("quorum must be >= 1")


@dataclass
class ReviewPolicyConfig:
    """Full review-policy configuration for one campaign."""

    mode: ReviewMode = ReviewMode.INDEPENDENT_FIRST
    panel_size: int = 4  # §10.5: four independent reviewers
    policies: dict[Phase, QuorumPolicy] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.panel_size < 1:
            raise ReviewPolicyError("panel_size must be >= 1")

    def policy_for(self, phase: Phase) -> QuorumPolicy:
        """Policy for a phase; defaults apply per-phase when unset."""
        return self.policies.get(phase, QuorumPolicy())


def _coerce_phase(phase: str | Phase) -> Phase:
    try:
        return phase if isinstance(phase, Phase) else Phase(phase)
    except ValueError as e:
        raise ReviewPolicyError(f"unknown review phase {phase!r}") from e


def _blind_count(reviews: list[dict]) -> int:
    """Number of blind (pre-disclosure) reviews in the record."""
    return sum(1 for r in reviews if r.get("blind", True))


class ReviewPolicyEngine:
    """Answers visibility and quorum questions against recorded reviews."""

    def __init__(self, config: ReviewPolicyConfig) -> None:
        self.config = config

    # -- visibility --------------------------------------------------------

    def check_visibility(
        self,
        phase: str | Phase,
        reviews: list[dict],
        *,
        saw_prior_reviews: bool,
    ) -> None:
        """Raise unless this reviewer was permitted to see prior results.

        In independent-first mode reviewers must stay blind until every
        panel review is collected (blind count reaches panel size) or the
        operator explicitly opens discussion (mode flipped). Discussion-
        first permits visibility unconditionally.
        """
        phase = _coerce_phase(phase)
        if self.config.mode is ReviewMode.DISCUSSION_FIRST:
            return
        if not saw_prior_reviews:
            return
        collected = _blind_count(reviews) >= self.config.panel_size
        if not collected:
            raise ReviewPolicyError(
                f"independent-first mode forbids seeing prior {phase.value} "
                f"reviews before blind collection completes "
                f"({_blind_count(reviews)}/{self.config.panel_size})"
            )

    def discussion_open(self, reviews: list[dict]) -> bool:
        """Whether cross-reviewer discussion may begin."""
        if self.config.mode is ReviewMode.DISCUSSION_FIRST:
            return True
        return _blind_count(reviews) >= self.config.panel_size

    # -- quorum --------------------------------------------------------------

    def evaluate(
        self,
        phase: str | Phase,
        reviews: list[dict],
    ) -> dict | None:
        """Evaluate the configured quorum policy for a panel phase.

        Returns a decision dict when the gate resolves (advance / quarantine
        style outcomes are the caller's mapping); ``None`` while more
        reviews are needed or the outcome is unresolved.

        Decision shapes::

            {"outcome": "advance",     "reason": ..., "accepts": N, ...}
            {"outcome": "reject_all",  ...}   # every reviewer rejected
            {"outcome": "unresolved",  ...}   # mixed, no quorum yet
        """
        phase = _coerce_phase(phase)
        if phase not in QUORUM_PHASES:
            raise ReviewPolicyError(f"phase {phase.value} has no quorum to evaluate")

        policy = self.config.policy_for(phase)
        accepts = sum(1 for r in reviews if r.get("verdict") == "accept")
        rejects = sum(1 for r in reviews if r.get("verdict") == "reject")
        blocking = any(r.get("blocking_safety_or_validity_objection") for r in reviews)
        total = len(reviews)

        base = {"accepts": accepts, "rejects": rejects, "total": total}

        if total < policy.quorum:
            return {"outcome": "pending", **base}

        # A blocking safety/validity objection vetoes advancement whenever
        # the policy forbids them — regardless of accept count (§10.5).
        if policy.forbid_blocking_objections and blocking:
            return {"outcome": "unresolved", "reason": "blocking_objection_veto", **base}

        required = len(reviews) if policy.require_all_accept else policy.quorum
        if accepts >= required:
            return {
                "outcome": "advance",
                "reason": ("all_accept" if policy.require_all_accept else "quorum_met_no_block"),
                **base,
            }
        if rejects == total:
            return {"outcome": "reject_all", "reason": "all_reject", **base}
        return {"outcome": "unresolved", "reason": "no_quorum", **base}
