"""Deterministic severity rubric (PLAN §10.3, issue #239).

Impact analysis needs consistent severity ratings so parallel agents and
reviewers do not produce divergent scores. This module encodes a rubric
that maps structured impact axes to a severity level deterministically —
same inputs always produce the same level, no model judgment in the loop.

Rubric design:

- **Impact axes** (each scored 0–3):
    * ``confidentiality`` / ``integrity`` / ``availability`` — CIA impact.
    * ``reachability`` — how directly an attacker can reach the flaw
      (0 = not reachable … 3 = remotely reachable by unauthenticated
      attacker).
    * ``preconditions`` — inverted axis: fewer/simpler preconditions score
      higher (0 = many hard preconditions … 3 = none).
- **Weighted sum** with fixed weights (CIA ×2 each, reachability ×1.5,
  preconditions ×1) mapped to severity bands. Weights are constants so
  every agent/reviewer computes identical levels.

Severity-change discipline:

- Any severity change between lifecycle stages must carry a rationale;
  ``apply_severity_change`` refuses to mutate without one and returns a
  diff entry (before/after + rationale) suitable for the append-only
  history so changes are diff-visible.

Reviewer disagreement:

- If reviewers propose severities spanning ≥ ``escalation_span``
  levels (default 2), the panel outcome is ESCALATE — never a silent
  average. Averages are only computed when the spread is below the
  escalation threshold.

Ambiguous-impact fixtures live in tests/test_severity_rubric.py: findings
whose impact axes under-specify the picture but which must still resolve
to one consistent level given the recorded axes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum

from findings.lifecycle import LifecycleError


class Severity(StrEnum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# Ordered low→high so spans/diffs are index arithmetic.
SEVERITY_ORDER: list[Severity] = [
    Severity.NONE,
    Severity.LOW,
    Severity.MEDIUM,
    Severity.HIGH,
    Severity.CRITICAL,
]

# Fixed weights: the three CIA axes dominate, reachability next,
# preconditions last. Public so operators can inspect, never mutate at
# runtime (rubric determinism depends on them staying put).
AXIS_WEIGHTS: dict[str, float] = {
    "confidentiality": 2.0,
    "integrity": 2.0,
    "availability": 2.0,
    "reachability": 1.5,
    "preconditions": 1.0,
}

REQUIRED_AXES = tuple(AXIS_WEIGHTS)

MAX_SCORE = sum(w * 3 for w in AXIS_WEIGHTS.values())  # 25.5

# Inclusive upper bounds per band over the weighted total.
SEVERITY_BANDS: list[tuple[float, Severity]] = [
    (0.0, Severity.NONE),
    (6.0, Severity.LOW),
    (12.0, Severity.MEDIUM),
    (19.0, Severity.HIGH),
    (float("inf"), Severity.CRITICAL),
]


class RubricError(LifecycleError):
    """Raised for malformed rubric inputs or invalid severity changes."""


@dataclass
class ImpactAssessment:
    """Structured impact axes from §10.3 analysis.

    All five axes are required on a 0–3 integer scale; missing or
    out-of-range values are rejected rather than defaulted so ambiguity
    is explicit, not silently absorbed.
    """

    confidentiality: int
    integrity: int
    availability: int
    reachability: int
    preconditions: int

    def __post_init__(self) -> None:
        for name in REQUIRED_AXES:
            value = getattr(self, name)
            if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= 3:
                raise RubricError(f"axis {name!r} must be an integer 0-3, got {value!r}")


def _axis_scores(assessment: ImpactAssessment) -> dict[str, int]:
    return {name: getattr(assessment, name) for name in REQUIRED_AXES}


def weighted_score(assessment: ImpactAssessment) -> float:
    """Deterministic weighted total for an assessment."""
    return round(sum(_axis_scores(assessment)[a] * w for a, w in AXIS_WEIGHTS.items()), 2)


def score_to_severity(score: float) -> Severity:
    """Map a weighted total to its band. Deterministic, order-independent."""
    for upper, sev in SEVERITY_BANDS:
        if score <= upper:
            return sev
    return SEVERITY_ORDER[-1]  # unreachable; keeps type-checkers happy


def assess_severity(assessment: ImpactAssessment) -> Severity:
    """Full rubric: axes → weighted score → severity band."""
    return score_to_severity(weighted_score(assessment))


def justification_prompt(severity: Severity) -> str:
    """Prompt fragment asking agents to justify against the rubric bands."""
    return (
        f"Assigned severity '{severity.value}'. Justify by citing each impact "
        f"axis ({', '.join(REQUIRED_AXES)}) with its 0-3 score and explain why "
        f"the weighted total falls in the '{severity.value}' band."
    )


# --- Severity changes across lifecycle stages -------------------------------


@dataclass
class SeverityChange:
    """Diff-visible record of a severity transition."""

    finding_id: str
    previous_severity: str
    new_severity: str
    rationale: str
    stage_from: str | None = None
    stage_to: str | None = None
    kind: str = "severity_change"


def apply_severity_change(
    finding_id: str,
    previous: Severity,
    new: Severity,
    rationale: str,
    *,
    stage_from: str | None = None,
    stage_to: str | None = None,
) -> SeverityChange:
    """Build the diff entry for a severity change.

    Refuses no-op changes (nothing to diff) and empty rationales — a
    severity move between lifecycle stages without stated reasoning is
    exactly the inconsistency this rubric exists to prevent. The caller
    appends the returned entry to the finding's history.
    """
    if previous == new:
        raise RubricError("severity unchanged; nothing to record")
    if not rationale or not rationale.strip():
        raise RubricError("severity change requires a non-empty rationale")
    if previous not in SEVERITY_ORDER or new not in SEVERITY_ORDER:
        raise RubricError(f"unknown severity in change {previous!r} -> {new!r}")
    return SeverityChange(
        finding_id=finding_id,
        previous_severity=previous.value,
        new_severity=new.value,
        rationale=rationale.strip(),
        stage_from=stage_from,
        stage_to=stage_to,
    )


# --- Reviewer disagreement --------------------------------------------------


@dataclass
class SeverityPanelOutcome:
    """Result of collecting severities from a review panel."""

    decision: str  # agree | escalate
    resolved_severity: str | None
    proposed: list[str] = field(default_factory=list)
    span: int = 0
    reason: str = ""


def evaluate_severity_panel(
    reviews: list[dict],
    *,
    escalation_span: int = 2,
) -> SeverityPanelOutcome:
    """Resolve panel severity proposals.

    Each review dict carries ``reviewer`` and ``proposed_severity``.
    When proposals span ≥ ``escalation_span`` levels the outcome is
    ESCALATE — we deliberately do NOT average, because averaging two
    'low' and one 'critical' into 'medium' launders disagreement into
    false precision. Below the threshold, agreement resolves to the
    consensus level when unanimous and to the median otherwise.
    """
    if not reviews:
        raise RubricError("severity panel requires at least one review")
    if escalation_span < 1:
        raise RubricError("escalation_span must be >= 1")

    proposed: list[Severity] = []
    for r in reviews:
        raw = r.get("proposed_severity")
        try:
            sev = Severity(raw)
        except ValueError:
            raise RubricError(
                f"reviewer {r.get('reviewer')!r} proposed unknown severity {raw!r}"
            ) from None
        proposed.append(sev)

    indices = sorted(SEVERITY_ORDER.index(s) for s in proposed)
    span = indices[-1] - indices[0]
    values = [s.value for s in proposed]

    if span >= escalation_span:
        return SeverityPanelOutcome(
            decision="escalate",
            resolved_severity=None,
            proposed=values,
            span=span,
            reason=(
                f"severity proposals span {span} levels (>= {escalation_span}); "
                "escalating instead of averaging"
            ),
        )

    if span == 0:
        return SeverityPanelOutcome(
            decision="agree",
            resolved_severity=proposed[0].value,
            proposed=values,
            span=0,
            reason="unanimous severity",
        )

    median = indices[len(indices) // 2]
    return SeverityPanelOutcome(
        decision="agree",
        resolved_severity=SEVERITY_ORDER[median].value,
        proposed=values,
        span=span,
        reason="minor disagreement below escalation threshold; resolved to median",
    )
