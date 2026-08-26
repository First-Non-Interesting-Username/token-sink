"""Review-quorum edge semantics (PLAN §10.5, issue #142).

Pins down the decisions PLAN.md leaves open so every review gate behaves
identically. Everything here is configurable via the ``review`` section
of §16 config with safe defaults.

Decision table (also documented in docs/review-quorum.md):

Given four PoC reviews each carrying ``verdict`` (accept/reject) and a
``blocking_safety_or_validity_objection`` flag:

| accepts | blocking? | outcome                          |
|---------|-----------|----------------------------------|
| 4       | any       | ADVANCE (unanimous beats block*) |
| 3       | none      | ADVANCE (quorum)                 |
| 3       | >=1       | HOLD  — quorum satisfied but a   |
|         |           | blocking objection overrides     |
| <=2     | any       | HOLD unless all-reject → REVERT/ |
|         |           | QUARANTINE per lifecycle rules   |

*Unanimous acceptance still advances only if policy allows overriding a
blocking objection; the safe default is that it does NOT — a single
blocking safety/validity objection always holds the finding regardless
of verdict count. ``allow_unanimous_over_block=True`` restores the
override for operators who want it.

Other pinned semantics:

- **Blocking fields**: structural, not free-text — a review blocks iff its
  ``blocking_safety_or_validity_objection`` flag is true. Severity/impact
  disagreement NEVER blocks (PLAN: attach dissent); only safety/validity
  objections do.
- **Re-review cap**: after an all-reject revert to post-first-review,
  at most ``max_re_review_cycles`` (default 2) further PoC-review cycles
  run. Exhausting the cap forces quarantine instead of looping forever.
- **Late dissent**: reviewers never mutate prior reviews. A changed
  verdict is appended as a new ``amendment`` entry referencing the
  original — append-only history stays intact.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from findings.lifecycle import LifecycleError

REVIEW_MODES = ("independent_first", "discussion_first")


@dataclass
class QuorumPolicy:
    """Configurable edge semantics for the four-agent PoC review."""

    # Numeric quorum of accepts required when no blocking objection exists.
    quorum_accepts: int = 3
    # Fields whose objection blocks advancement. Only safety/validity count;
    # severity conflicts attach as dissent and never block.
    blocking_fields: tuple[str, ...] = ("validity", "safety")
    # Max PoC re-review cycles after an all-reject revert before forced
    # quarantine. Prevents infinite revert loops.
    max_re_review_cycles: int = 2
    # If True, 4/4 unanimous accept overrides a single blocking objection.
    # Default False: one safety/validity block always holds the finding.
    allow_unanimous_over_block: bool = False
    # independent_first collects blind reviews before discussion.
    mode: str = "independent_first"
    # How many blind reviews must be collected before discussion opens in
    # independent_first mode (the full panel by default).
    blind_review_count: int = 4

    def __post_init__(self) -> None:
        if self.mode not in REVIEW_MODES:
            raise LifecycleError(f"unknown review mode {self.mode!r}")
        if self.quorum_accepts < 1:
            raise LifecycleError("quorum_accepts must be >= 1")
        if self.max_re_review_cycles < 0:
            raise LifecycleError("max_re_review_cycles must be >= 0")
        if self.blind_review_count < 1:
            raise LifecycleError("blind_review_count must be >= 1")

    def is_blocking(self, review: dict) -> bool:
        """A review blocks iff its flag is set AND it cites a blocking field."""
        if not review.get("blocking_safety_or_validity_objection"):
            return False
        field_cited = review.get("objection_field")
        # Legacy reviews carry no objection_field; treat the flag alone as
        # blocking (conservative — favors holding over advancing).
        if field_cited is None:
            return True
        return field_cited in self.blocking_fields


@dataclass
class QuorumOutcome:
    """Deterministic result of evaluating a full review panel."""

    decision: str  # advance | hold | force_quarantine
    reason: str
    blocking_reviewers: list[str] = field(default_factory=list)
    accepts: int = 0
    rejects: int = 0


def evaluate_quorum(
    reviews: list[dict],
    policy: QuorumPolicy,
    *,
    re_review_cycles_used: int = 0,
    panel_size: int = 4,
) -> QuorumOutcome:
    """Apply the decision table to a complete review panel.

    Deterministic on (accepts, blocking, re-review cycles used) only —
    review order never matters.
    """
    if len(reviews) < panel_size:
        raise LifecycleError(f"need {panel_size} reviews, have {len(reviews)}")
    verdicts = [r["verdict"] for r in reviews]
    accepts = sum(v == "accept" for v in verdicts)
    rejects = len(reviews) - accepts
    blockers = [r["reviewer"] for r in reviews if policy.is_blocking(r)]

    # Unanimous accept path.
    if accepts == panel_size and rejects == 0:
        if blockers and not policy.allow_unanimous_over_block:
            return QuorumOutcome(
                "hold",
                "unanimous_accept_but_blocking_objection",
                blockers,
                accepts,
                rejects,
            )
        return QuorumOutcome(
            "advance",
            "quorum_unanimous_accept" + ("_over_block" if blockers else ""),
            blockers,
            accepts,
            rejects,
        )

    # Any blocking objection overrides a mere quorum (safe default).
    if accepts >= policy.quorum_accepts and not blockers:
        return QuorumOutcome("advance", "quorum_majority_no_block", blockers, accepts, rejects)
    if accepts >= policy.quorum_accepts and blockers:
        return QuorumOutcome(
            "hold", "quorum_met_but_blocking_objection", blockers, accepts, rejects
        )

    # Below quorum: all-reject triggers the revert/quarantine fork.
    if rejects == panel_size:
        if re_review_cycles_used < policy.max_re_review_cycles:
            return QuorumOutcome(
                "hold",
                f"all_reject_revert_cycle_{re_review_cycles_used + 1}_of_"
                f"{policy.max_re_review_cycles}",
                blockers,
                accepts,
                rejects,
            )
        return QuorumOutcome(
            "force_quarantine",
            "all_reject_re_review_cap_exhausted",
            blockers,
            accepts,
            rejects,
        )

    return QuorumOutcome("hold", "below_quorum_pending_evidence", blockers, accepts, rejects)


def can_open_discussion(policy: QuorumPolicy, collected_reviews: int) -> bool:
    """Discussion gating for independent-first mode."""
    if policy.mode == "discussion_first":
        return True
    return collected_reviews >= policy.blind_review_count


def record_late_dissent(
    finding_reviews: list[dict], reviewer: str, new_verdict: str, note: str = ""
) -> dict:
    """Append (never mutate) a verdict amendment after advancement.

    Returns the amendment entry for the caller to append to the finding's
    reviews list. The original entry stays untouched so append-only
    history is preserved.
    """
    prior = [r for r in finding_reviews if r.get("reviewer") == reviewer]
    if not prior:
        raise LifecycleError(f"no prior review from {reviewer} to amend")
    amendment = {
        "kind": "amendment",
        "reviewer": reviewer,
        "amends_review_index": finding_reviews.index(prior[-1]),
        "previous_verdict": prior[-1]["verdict"],
        "verdict": new_verdict,
        "note": note,
        "timestamp_source": "caller",
    }
    return amendment
