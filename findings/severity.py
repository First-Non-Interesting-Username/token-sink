"""Deterministic severity scoring rubric (PLAN §10.3, issue #239).

Impact analysis (§10.3) needs a consistent severity rating so parallel
agents/reviewers do not produce inconsistent scores. This module encodes a
versioned rubric over explicit impact axes — confidentiality/integrity/
availability impact, reachability, and preconditions — and maps them
deterministically to severity levels.

Design:

- `assess()` computes the severity from an axis dict; identical inputs always
  produce identical outputs (no model judgment inside this module).
- Severity changes between lifecycle stages go through `record_severity()`,
  which requires a written rationale and appends to the finding's history so
  the change is diff-visible in the transition log.
- Reviewer severity disagreement is compared with
  `escalation_required()`: when reviewers disagree by >= ESCALATION_GAP
  levels the result is an escalation event, never a silent average.
"""

from __future__ import annotations

from enum import IntEnum
from typing import Any

# How many severity levels of reviewer disagreement trigger escalation.
ESCALATION_GAP = 2

RUBRIC_VERSION = "1"


class Severity(IntEnum):
    """Ordered severity levels; numeric value enables gap arithmetic."""

    NONE = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str | int | Severity) -> Severity:
        if isinstance(value, cls):
            return value
        try:
            return cls[str(value).upper()]
        except KeyError:
            raise ValueError(f"unknown severity {value!r}") from None


# Axis weights are intentionally NOT a weighted sum: severity is anchored on
# the strongest security impact (max of C/I/A), then adjusted by exploitability
# axes. A weighted average lets a single loud axis be diluted by quiet ones,
# which is exactly how ambiguous findings end up scored inconsistently.
REACHABILITY_BUMP_THRESHOLD = 3  # remote/unauthenticated path: +1 level
PRECONDITION_DAMP_THRESHOLD = 3  # heavy preconditions: -1 level

AXIS_NAMES = ("confidentiality", "integrity", "availability", "reachability", "preconditions")

IMPACT_AXES = ("confidentiality", "integrity", "availability")

MAX_AXIS_SCORE = 4  # axes are scored 0-4


def _axis_score(axis: Any) -> int:
    """Normalize one axis input (int 0-4 or none/low/medium/high/critical)."""
    words = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    if isinstance(axis, bool):  # guard: bool is an int subclass
        raise ValueError(f"invalid axis score {axis!r}")
    if isinstance(axis, int):
        if not 0 <= axis <= MAX_AXIS_SCORE:
            raise ValueError(f"axis score out of range: {axis!r}")
        return axis
    key = str(axis).strip().lower()
    if key not in words:
        raise ValueError(f"invalid axis score {axis!r}")
    return words[key]


# Justification prompts shown to agents producing the assessment; every
# non-none axis answer must be backed by these questions (PLAN §10.3 fields).
JUSTIFICATION_PROMPTS: dict[str, str] = {
    "confidentiality": "What data could an attacker read, and is it sensitive?",
    "integrity": "What state or data could an attacker modify without detection?",
    "availability": "Could the attacker deny service, and at what cost to restore?",
    "reachability": "Is the vulnerable path reachable remotely, unauthenticated?",
    "preconditions": "What must already be true (privileges, user interaction) to exploit?",
}


class SeverityError(Exception):
    """Raised for invalid rubric inputs or missing change rationale."""


def assess(axes: dict[str, Any]) -> dict[str, Any]:
    """Deterministically map impact axes to a severity level.

    Returns a record containing the rubric version, normalized axis scores,
    the impact anchor, the resulting severity, and the justification prompts
    that must be answered for any nonzero axis.
    """
    missing = set(AXIS_NAMES) - set(axes)
    extra = set(axes) - set(AXIS_NAMES)
    if missing:
        raise SeverityError(f"missing axes: {sorted(missing)}")
    if extra:
        raise SeverityError(f"unknown axes: {sorted(extra)}")
    scores = {name: _axis_score(axes[name]) for name in AXIS_NAMES}
    # Anchor on the strongest security impact, then apply exploitability
    # adjustments. Clamped so NONE can't be bumped and CRITICAL can't drop.
    impact = max(scores[a] for a in IMPACT_AXES)
    level = impact
    if scores["reachability"] >= REACHABILITY_BUMP_THRESHOLD:
        level += 1
    if scores["preconditions"] >= PRECONDITION_DAMP_THRESHOLD:
        level -= 1
    severity = Severity(max(0, min(int(Severity.CRITICAL), level)))
    return {
        "rubric_version": RUBRIC_VERSION,
        "axes": scores,
        "impact_anchor": Severity(impact).name if impact else "NONE",
        "severity": severity.name,
        "severity_level": int(severity),
        "justification_prompts": [
            JUSTIFICATION_PROMPTS[name] for name, s in scores.items() if s > 0
        ],
    }


def record_severity(
    finding: Any,
    store: Any,
    actor_uuid: str,
    axes: dict[str, Any],
    rationale: str,
    stage: str = "",
) -> dict[str, Any]:
    """Attach a rubric-derived severity to a finding with required rationale.

    Every severity entry (initial or changed) records the full assessment,
    the rationale, and the previous severity so the append-only history shows
    a diff-visible trail. A severity *change* without a non-empty rationale
    raises SeverityError — silent re-scoring is exactly what §10.3 forbids.
    """
    if not isinstance(rationale, str) or not rationale.strip():
        prev = getattr(finding, "severity", None)
        if prev is not None:
            raise SeverityError("severity change requires a written rationale")
        raise SeverityError("severity assessment requires a written rationale")
    result = assess(axes)
    entry = {
        "stage": stage or getattr(finding, "state", ""),
        "actor": actor_uuid,
        "previous_severity": getattr(finding, "severity", None),
        **result,
        "rationale": rationale.strip(),
    }
    finding.severity = result["severity"]
    return entry


def escalation_required(severities: list[str | int | Severity]) -> dict[str, Any]:
    """Decide whether reviewer severity spread warrants escalation.

    Reviewers disagreeing by >= ESCALATION_GAP levels escalate instead of
    being averaged away. Returns a structured verdict either way.
    """
    if len(severities) < 2:
        raise SeverityError("need at least two reviewer severities")
    levels = sorted(Severity.parse(s).value for s in severities)
    spread = levels[-1] - levels[0]
    escalated = spread >= ESCALATION_GAP
    verdict: dict[str, Any] = {
        "escalated": escalated,
        "spread": spread,
        "min": Severity(levels[0]).name,
        "max": Severity(levels[-1]).name,
    }
    if escalated:
        verdict["reason"] = (
            f"reviewer severity spread of {spread} levels "
            f"({verdict['min']} vs {verdict['max']}) exceeds the "
            f"escalation gap of {ESCALATION_GAP}; human/arbitration review required"
        )
    else:
        verdict["resolution"] = Severity((levels[0] + levels[-1]) // 2).name
    return verdict
