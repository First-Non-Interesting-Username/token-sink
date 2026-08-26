<<<<<<< HEAD
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
=======
"""Deterministic finding-severity rubric (PLAN §10.3, issue #239).

Maps structured impact evidence to a severity level so parallel
agents/reviewers rate the same finding consistently instead of by vibe.

Impact axes (each scored from explicit, checkable facts — never free text):

- **CIA impact** (confidentiality / integrity / availability): each rated
  ``none`` / ``low`` / ``high``. Any ``high`` dominates: it caps the floor
  severity at HIGH for that axis's contribution.
- **Reachability**: ``remote_no_auth`` > ``remote_auth`` >
  ``local`` > ``theoretical``.
- **Preconditions**: how much an attacker needs beyond network access —
  user interaction, unusual configuration, or privileged access each
  pull the level down.

The rubric is a pure function: same inputs → same level, every time, on
every agent. Justification prompts are emitted alongside the score so a
caller (agent or reviewer UI) knows exactly which axes must be argued.

Severity transitions between lifecycle stages require a written rationale
and are recorded as diff-visible history entries (old → new + why).
Reviewer disagreement of >= ``escalation_threshold`` levels triggers
``ESCALATE`` rather than silent averaging — the spread is surfaced to a
human adjudicator.
>>>>>>> origin/main
"""

from __future__ import annotations

<<<<<<< HEAD
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
=======
import hashlib
import json
from dataclasses import dataclass, field
from enum import StrEnum


class RubricError(Exception):
    """Raised when rubric inputs are structurally invalid."""


class Severity(StrEnum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


SEVERITY_ORDER = list(Severity)


class Impact(StrEnum):
    NONE = "none"
    LOW = "low"
    HIGH = "high"


class Reachability(StrEnum):
    THEORETICAL = "theoretical"
    LOCAL = "local"
    REMOTE_AUTH = "remote_auth"
    REMOTE_NO_AUTH = "remote_no_auth"


@dataclass(frozen=True)
class ImpactAssessment:
    """Structured impact evidence — the rubric's only input."""

    confidentiality: Impact
    integrity: Impact
    availability: Impact
    reachability: Reachability
    # Each True pulls the final level down one notch (floor at LOW):
    # attacker needs user interaction / non-default config / privileges.
    requires_user_interaction: bool = False
    requires_unusual_config: bool = False
    requires_privileged_access: bool = False

    def fingerprint(self) -> str:
        """Stable content hash so equal assessments dedupe in fixtures."""
        payload = json.dumps(
            {
                "c": self.confidentiality.value,
                "i": self.integrity.value,
                "a": self.availability.value,
                "r": self.reachability.value,
                "u": self.requires_user_interaction,
                "g": self.requires_unusual_config,
                "p": self.requires_privileged_access,
            },
            sort_keys=True,
        )
        return hashlib.sha256(payload.encode()).hexdigest()


# Reachability bonus on top of the CIA impact floor: an remotely-exploitable,
# unauthenticated issue rates one notch above the same impact behind a local shell.
_REACHABILITY_BONUS: dict[Reachability, int] = {
    Reachability.REMOTE_NO_AUTH: 1,
    Reachability.REMOTE_AUTH: 0,
    Reachability.LOCAL: 0,
    Reachability.THEORETICAL: 0,
}

# Preconditions that reduce the level, applied in order.
_PRECONDITION_PENALTIES = (
    "requires_user_interaction",
    "requires_unusual_config",
    "requires_privileged_access",
)

# Axes whose HIGH rating must be explicitly justified by callers.
JUSTIFICATION_PROMPTS = {
    "confidentiality": "What data is exposed, and to whom?",
    "integrity": "What state can be tampered with, and persistently?",
    "availability": "How can the service be disrupted, and how durably?",
    "reachability": "What is the shortest concrete attack path?",
}


def score_severity(assessment: ImpactAssessment) -> tuple[Severity, list[str]]:
    """Deterministically map an assessment to (severity, justifications).

    The returned justification strings name every axis that drove the
    result, so the rating is auditable and reviewers argue facts, not adjectives.
    """
    if not isinstance(assessment, ImpactAssessment):
        raise RubricError("assessment must be an ImpactAssessment")

    # CIA impact floor: high=2 / low=1 per axis, summed, capped at 4.
    # Without at least one HIGH axis the floor caps at MEDIUM — a purely
    # low-impact finding never rates above it regardless of reachability.
    cia_high = sum(
        1
        for axis in ("confidentiality", "integrity", "availability")
        if getattr(assessment, axis) == Impact.HIGH
    )
    cia_low = sum(
        1
        for axis in ("confidentiality", "integrity", "availability")
        if getattr(assessment, axis) == Impact.LOW
    )
    level = min(2 * cia_high + cia_low, 4)
    if cia_high == 0:
        level = min(level, 2)
    justifications = [f"CIA impact floor {level}/4 ({cia_high} high, {cia_low} low axes)"]

    bonus = _REACHABILITY_BONUS[assessment.reachability]
    if bonus:
        level += bonus
    justifications.append(f"reachability={assessment.reachability.value} adds +{bonus}")

    for pre in _PRECONDITION_PENALTIES:
        if getattr(assessment, pre):
            level -= 1
            justifications.append(f"{pre} reduces -1")

    level = max(0, min(4, level))
    severity = SEVERITY_ORDER[level]
    return severity, justifications


def justification_prompts(assessment: ImpactAssessment) -> dict[str, str]:
    """Prompts the caller must answer when filing/arguing this rating."""
    prompts: dict[str, str] = {}
    for axis in ("confidentiality", "integrity", "availability"):
        if getattr(assessment, axis) != Impact.NONE:
            prompts[axis] = JUSTIFICATION_PROMPTS[axis]
    prompts["reachability"] = JUSTIFICATION_PROMPTS["reachability"]
    return prompts


# ---------------------------------------------------------------------------
# Transition history: rationale-required, diff-visible
# ---------------------------------------------------------------------------


@dataclass
class SeverityTransition:
    """One append-only severity change with its required rationale."""

    from_level: Severity
    to_level: Severity
    rationale: str
    stage: str  # lifecycle stage the change happened in, e.g. "impact_analysis"

    def __post_init__(self) -> None:
        if not self.rationale or not self.rationale.strip():
            raise RubricError("severity changes require a written rationale")

    def diff_line(self) -> str:
        """Human-diffable rendering for report review."""
        arrow = "upgraded" if self.delta() > 0 else "downgraded"
        return (
            f"[{self.stage}] {self.from_level.value} -> {self.to_level.value} "
            f"({arrow}): {self.rationale.strip()}"
        )

    def delta(self) -> int:
        return SEVERITY_ORDER.index(self.to_level) - SEVERITY_ORDER.index(self.from_level)


@dataclass
class SeverityHistory:
    """Append-only severity timeline for one finding."""

    initial: Severity
    entries: list[SeverityTransition] = field(default_factory=list)

    @property
    def current(self) -> Severity:
        return self.entries[-1].to_level if self.entries else self.initial

    def transition(self, to_level: Severity, rationale: str, stage: str) -> SeverityTransition:
        change = SeverityTransition(
            from_level=self.current, to_level=to_level, rationale=rationale, stage=stage
        )
        self.entries.append(change)
        return change

    def diff(self) -> list[str]:
        """Full diff view; empty when the level never changed."""
        return [e.diff_line() for e in self.entries]


# ---------------------------------------------------------------------------
# Reviewer disagreement → escalation, never silent averaging
# ---------------------------------------------------------------------------

DEFAULT_ESCALATION_THRESHOLD = 2


@dataclass(frozen=True)
class SeverityVote:
    reviewer_id: str
    level: Severity
    rationale: str = ""


def evaluate_disagreement(
    votes: list[SeverityVote], threshold: int = DEFAULT_ESCALATION_THRESHOLD
) -> tuple[str, Severity | None]:
    """Decide ADVANCE vs ESCALATE from reviewer severity votes.

    Returns ``(decision, consensus_or_none)``:

    - spread < threshold  → ``ADVANCE`` with the median vote as consensus;
      minority rationales stay attached as dissent (never dropped).
    - spread >= threshold → ``ESCALATE`` with no consensus level; a human
      adjudicates. Averaging would invent agreement nobody expressed.
    """
    if len(votes) < 2:
        raise RubricError("at least two reviewer votes are required")
    levels = sorted(SEVERITY_ORDER.index(v.level) for v in votes)
    spread = levels[-1] - levels[0]
    if spread >= threshold:
        return "ESCALATE", None
    mid = len(levels) // 2
    median_index = levels[mid] if len(levels) % 2 == 1 else (levels[mid - 1] + levels[mid]) // 2
    return "ADVANCE", SEVERITY_ORDER[median_index]


def dissenting_rationales(votes: list[SeverityVote], consensus: Severity) -> list[str]:
    """Rationales from voters who disagree with the consensus — kept visible."""
    return [f"{v.reviewer_id}: {v.rationale}" for v in votes if v.level != consensus]
>>>>>>> origin/main
