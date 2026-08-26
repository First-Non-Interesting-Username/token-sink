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
"""

from __future__ import annotations

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
