"""Review-mode configuration & quorum policy engine (PLAN §10.2/§10.5).

Two review modes govern whether PoC reviewers can see prior results:

    independent-first — blind collection first; discussion only after all
                        reviews are in (the PLAN default).
    discussion-first  — reviewers may challenge/refine each other from the
                        start.

On top of the mode sits a quorum policy deciding when a review round is
satisfied:

    - unanimous acceptance always advances;
    - otherwise a configurable quorum of accepts with no blocking safety or
      validity objection advances (§10.5 default);
    - ``require_all_accept`` forbids the majority path entirely;
    - model-family diversity can be demanded across a full reviewer panel
      (issue #122 tracks enforcement for reviewer panels; here we provide the
      check the panel builder calls before dispatch);
    - re-review caps bound how many times a finding may be re-reviewed after
      an unresolved round, so a deadlocked panel cannot spin forever.

This module is deliberately storage-free: it evaluates policies against plain
review dicts so it can sit in front of any lifecycle/store implementation.
"""

from __future__ import annotations

from dataclasses import dataclass, field


class ReviewPolicyError(Exception):
    """Raised for invalid configuration or inapplicable evaluations."""


# Modes in which reviewers are allowed to see prior reviews *during* the round.
MODES = {"independent_first", "discussion_first"}


@dataclass
class ReviewModeConfig:
    """Operator-facing knobs. Mirrors ``config.loader.ReviewConfig`` fields."""

    mode: str = "independent_first"
    quorum: int = 2
    require_all_accept: bool = False
    require_model_family_diversity: bool = False
    max_reReviews: int = 1
    # Extra keys recorded but not interpreted by this engine.
    extras: dict = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.mode not in MODES:
            raise ReviewPolicyError(f"unknown review mode: {self.mode!r}")
        if self.quorum < 1:
            raise ReviewPolicyError("quorum must be >= 1")
        if self.max_reReviews < 0:
            raise ReviewPolicyError("max_reReviews must be >= 0")
        if self.require_all_accept:
            # Unanimity makes the numeric quorum meaningless; keep them honest.
            self.quorum = max(self.quorum, 2)

    def can_see_prior_reviews(self) -> bool:
        """Whether reviewers may read earlier in-round results."""
        return self.mode == "discussion_first"


@dataclass
class QuorumDecision:
    """Result of evaluating one review round."""

    outcome: str  # advance | unresolved | quarantine | revert
    reason: str
    accepts: int
    rejects: int
    abstains: int
    blocking_objections: int
    unique_reviewers: int
    model_families: list[str]
    diversity_ok: bool


def evaluate_quorum(
    reviews: list[dict],
    cfg: ReviewModeConfig,
    panel_size: int,
) -> QuorumDecision:
    """Evaluate one completed review round against the configured policy.

    ``reviews`` entries need: ``verdict`` (accept/reject/abstain),
    ``blocking_safety_or_validity_objection`` (bool), ``reviewer_agent_uuid``,
    and optionally ``model_family``. ``panel_size`` is the configured number of
    reviewers for the phase (4 for PoC review per §10.5).
    """
    if len(reviews) != panel_size:
        raise ReviewPolicyError(
            f"need exactly {panel_size} reviews to evaluate, got {len(reviews)}"
        )

    verdicts = [r["verdict"] for r in reviews]
    blocking = sum(1 for r in reviews if r.get("blocking_safety_or_validity_objection"))
    accepts = sum(1 for v in verdicts if v == "accept")
    rejects = sum(1 for v in verdicts if v == "reject")
    abstains = sum(1 for v in verdicts if v == "abstain")

    uuids = [r["reviewer_agent_uuid"] for r in reviews]
    if len(set(uuids)) != len(uuids):
        raise ReviewPolicyError("duplicate reviewer agent UUIDs in one round")
    unique_reviewers = len(set(uuids))

    families = sorted({r["model_family"] for r in reviews if r.get("model_family")})
    diversity_ok = len(families) >= 2 or not cfg.require_model_family_diversity
    if cfg.require_model_family_diversity and not families:
        raise ReviewPolicyError("model_family required on every review when diversity is enforced")
    if cfg.require_model_family_diversity and not diversity_ok:
        raise ReviewPolicyError(
            "panel lacks model-family diversity; rebuild panel before evaluation"
        )

    # Unanimous acceptance advances regardless of other settings.
    if accepts == panel_size and rejects == 0 and abstains == 0:
        return QuorumDecision(
            "advance",
            "unanimous_accept",
            accepts,
            rejects,
            abstains,
            blocking,
            unique_reviewers,
            families,
            diversity_ok,
        )

    if rejects == panel_size:
        return QuorumDecision(
            "quarantine",
            "all_reject",
            accepts,
            rejects,
            abstains,
            blocking,
            unique_reviewers,
            families,
            diversity_ok,
        )

    if cfg.require_all_accept:
        return QuorumDecision(
            "unresolved",
            "require_all_accept_not_met",
            accepts,
            rejects,
            abstains,
            blocking,
            unique_reviewers,
            families,
            diversity_ok,
        )

    if accepts >= cfg.quorum and blocking == 0:
        return QuorumDecision(
            "advance",
            "quorum_no_block",
            accepts,
            rejects,
            abstains,
            blocking,
            unique_reviewers,
            families,
            diversity_ok,
        )

    if blocking > 0 and accepts >= cfg.quorum:
        return QuorumDecision(
            "unresolved",
            "blocked_by_objection",
            accepts,
            rejects,
            abstains,
            blocking,
            unique_reviewers,
            families,
            diversity_ok,
        )

    return QuorumDecision(
        "unresolved",
        "insufficient_accepts",
        accepts,
        rejects,
        abstains,
        blocking,
        unique_reviewers,
        families,
        diversity_ok,
    )


def re_reviews_used(rounds: list[list[dict]]) -> int:
    """How many re-review rounds a finding has already consumed.

    ``rounds`` is the ordered list of per-round review lists (each a completed
    panel). The initial round costs nothing; every subsequent round is a
    re-review.
    """
    return max(0, len(rounds) - 1)


def can_start_reReview(rounds: list[list[dict]], cfg: ReviewModeConfig) -> bool:
    """Whether another re-review round is allowed under the cap."""
    used = re_reviews_used(rounds)
    if used >= cfg.max_reReviews:
        return False
    # A round that already advanced/quarantined must not be followed by more.
    if rounds:
        last = rounds[-1]
        verdicts = [r["verdict"] for r in last]
        if all(v == "accept" for v in verdicts):
            return False
        if all(v == "reject" for v in verdicts):
            return False
    return True
