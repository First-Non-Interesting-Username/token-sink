"""Reviews subsystem (spec §10.2, §10.4).

A :class:`schema.Review` row is one agent's verdict against a specific
``(finding_id, version)``. Four reviews are required before a PoC can
advance to polishing; their verdicts are folded into a single
:class:`ReviewSummary` that captures the quorum outcome and any
blocking issues.

The helpers here own:

* inserting reviews (with the unique ``(finding_id, version,
  reviewer_agent_id)`` constraint to prevent duplicate reviews from
  the same agent),
* listing reviews,
* computing the quorum summary, and
* dispute reviews for the dual-confirmation deletion safeguard.
"""
from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import aiosqlite

from mavr.observability.logging import get_logger
from mavr.schemas import entities as schema

log = get_logger(__name__)


class ReviewError(RuntimeError):
    """Raised when a review is invalid or the quorum cannot be computed."""


# Quorum policies. The string form is what gets persisted in config and
# the finding_review_summaries table so users can audit it.
QUORUM_ALL_ACCEPT: str = "all_accept"
QUORUM_ALL_ACCEPT_OR_3_OF_4_NO_BLOCKERS: str = "all_accept_or_3_of_4_no_blockers"

KNOWN_QUORUM_POLICIES: frozenset[str] = frozenset(
    {QUORUM_ALL_ACCEPT, QUORUM_ALL_ACCEPT_OR_3_OF_4_NO_BLOCKERS}
)

# Review outcomes (post-quorum). The summary's ``outcome`` column takes
# exactly one of these values.
OUTCOME_ADVANCE: str = "advance"
OUTCOME_REQUEST_CHANGES: str = "request_changes"
OUTCOME_QUARANTINE: str = "quarantine"
OUTCOME_INCONCLUSIVE: str = "inconclusive"


@dataclass(frozen=True)
class ReviewSummary:
    finding_id: str
    version: int
    mode: str
    quorum_policy: str
    reviewer_count: int
    accept_count: int
    reject_count: int
    request_changes_count: int
    blocking_issues: list[str] = field(default_factory=list)
    outcome: str = OUTCOME_INCONCLUSIVE
    has_dispute: bool = False
    dispute_count: int = 0
    reviews: tuple[schema.Review, ...] = field(default_factory=tuple)
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def to_record(self) -> dict[str, Any]:
        return {
            "id": str(uuid4()),
            "schema_version": schema.SCHEMA_VERSION,
            "finding_id": self.finding_id,
            "version": self.version,
            "mode": self.mode,
            "quorum_policy": self.quorum_policy,
            "reviewer_count": self.reviewer_count,
            "accept_count": self.accept_count,
            "reject_count": self.reject_count,
            "request_changes_count": self.request_changes_count,
            "blocking_issues": json.dumps(self.blocking_issues),
            "outcome": self.outcome,
            "has_dispute": 1 if self.has_dispute else 0,
            "dispute_count": self.dispute_count,
            "created_at": self.created_at.isoformat(),
        }


def _now() -> datetime:
    return datetime.now(UTC)


def _row_to_review(row: aiosqlite.Row) -> schema.Review:
    missing = json.loads(row["missing_evidence"]) if row["missing_evidence"] else []
    return schema.Review(
        id=row["id"],
        schema_version=row["schema_version"],
        finding_id=row["finding_id"],
        version=row["version"],
        reviewer_agent_id=row["reviewer_agent_id"],
        verdict=schema.ReviewVerdict(row["verdict"]),
        validity=row["validity"],
        reproduction_quality=row["reproduction_quality"],
        scope_safety=row["scope_safety"],
        severity_consistency=row["severity_consistency"],
        missing_evidence=missing,
        requested_changes=row["requested_changes"] or "",
        confidence=row["confidence"],
        provider_id=row["provider_id"],
        model_id=row["model_id"],
        rationale=row["rationale"] or "",
        is_dispute=bool(row["is_dispute"]),
        created_at=datetime.fromisoformat(row["created_at"]),
    )


async def insert(
    conn: aiosqlite.Connection,
    *,
    finding_id: str,
    version: int,
    reviewer_agent_id: str,
    verdict: schema.ReviewVerdict,
    validity: str,
    reproduction_quality: str,
    scope_safety: str,
    severity_consistency: str,
    missing_evidence: list[str] | None = None,
    requested_changes: str = "",
    confidence: float = 0.0,
    provider_id: str | None = None,
    model_id: str | None = None,
    rationale: str = "",
    is_dispute: bool = False,
    dispute_target_id: str | None = None,
) -> schema.Review:
    rid = str(uuid4())
    now = _now()
    try:
        await conn.execute(
            "INSERT INTO reviews("
            "id, schema_version, finding_id, version, reviewer_agent_id, verdict, "
            "validity, reproduction_quality, scope_safety, severity_consistency, "
            "missing_evidence, requested_changes, confidence, provider_id, model_id, "
            "rationale, is_dispute, dispute_target_id, created_at"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                rid,
                schema.SCHEMA_VERSION,
                finding_id,
                version,
                reviewer_agent_id,
                verdict.value,
                validity,
                reproduction_quality,
                scope_safety,
                severity_consistency,
                json.dumps(missing_evidence or []),
                requested_changes,
                confidence,
                provider_id,
                model_id,
                rationale,
                1 if is_dispute else 0,
                dispute_target_id,
                now.isoformat(),
            ),
        )
    except aiosqlite.IntegrityError as exc:
        raise ReviewError(
            f"duplicate review for finding={finding_id} version={version} "
            f"reviewer={reviewer_agent_id}: {exc}"
        ) from exc
    await conn.commit()
    return schema.Review(
        id=rid,
        schema_version=schema.SCHEMA_VERSION,
        finding_id=finding_id,
        version=version,
        reviewer_agent_id=reviewer_agent_id,
        verdict=verdict,
        validity=validity,  # type: ignore[arg-type]
        reproduction_quality=reproduction_quality,  # type: ignore[arg-type]
        scope_safety=scope_safety,  # type: ignore[arg-type]
        severity_consistency=severity_consistency,  # type: ignore[arg-type]
        missing_evidence=list(missing_evidence or []),
        requested_changes=requested_changes,
        confidence=confidence,
        provider_id=provider_id,
        model_id=model_id,
        rationale=rationale,
        is_dispute=is_dispute,
        created_at=now,
    )


async def list_for_finding_version(
    conn: aiosqlite.Connection, *, finding_id: str, version: int
) -> list[schema.Review]:
    cur = await conn.execute(
        "SELECT * FROM reviews WHERE finding_id = ? AND version = ? "
        "ORDER BY created_at",
        (finding_id, version),
    )
    return [_row_to_review(r) for r in await cur.fetchall()]


async def list_all_for_finding(
    conn: aiosqlite.Connection, finding_id: str
) -> list[schema.Review]:
    cur = await conn.execute(
        "SELECT * FROM reviews WHERE finding_id = ? ORDER BY version, created_at",
        (finding_id,),
    )
    return [_row_to_review(r) for r in await cur.fetchall()]


# ---- quorum -------------------------------------------------------------


def _has_blocking_issue(review: schema.Review) -> bool:
    """A review is *blocking* if it raises a safety/validity concern.

    A blocking safety/validity issue overrides quorum — see spec §10.4.
    Only safety/validity fields qualify; a bare ``verdict=reject`` is
    counted in the reject tally but does not by itself override
    quorum (a reviewer may simply disagree).
    """
    if review.scope_safety == "unsafe":
        return True
    if review.validity == "invalid":
        return True
    if review.severity_consistency == "inconsistent":
        return True
    return False


def compute_summary(
    reviews: Iterable[schema.Review],
    *,
    finding_id: str,
    version: int,
    mode: str,
    quorum_policy: str,
) -> ReviewSummary:
    """Fold a list of reviews into a :class:`ReviewSummary`.

    Blocking logic (spec §10.4):

    * Any review with ``scope_safety == "unsafe"`` or ``validity ==
      "invalid"`` raises a blocking issue.
    * If a blocking issue is present, the outcome is
      ``quarantine`` even if 3-of-4 would otherwise accept.
    * Quorum policies: see :data:`KNOWN_QUORUM_POLICIES`.
    """
    if quorum_policy not in KNOWN_QUORUM_POLICIES:
        raise ReviewError(f"unknown quorum policy: {quorum_policy!r}")
    if mode not in {"independent_first", "discussion_first"}:
        raise ReviewError(f"unknown review mode: {mode!r}")

    review_list = list(reviews)
    accept = sum(1 for r in review_list if r.verdict == schema.ReviewVerdict.ACCEPT)
    reject = sum(1 for r in review_list if r.verdict == schema.ReviewVerdict.REJECT)
    changes = sum(
        1
        for r in review_list
        if r.verdict == schema.ReviewVerdict.REQUEST_CHANGES
    )
    blocking = [r for r in review_list if _has_blocking_issue(r)]
    dispute_count = sum(1 for r in review_list if r.is_dispute)

    if blocking:
        outcome = OUTCOME_QUARANTINE
    else:
        if quorum_policy == QUORUM_ALL_ACCEPT:
            if reject == 0 and changes == 0 and accept == len(review_list) and accept > 0:
                outcome = OUTCOME_ADVANCE
            elif reject == len(review_list) and reject > 0:
                outcome = OUTCOME_QUARANTINE
            elif changes > 0:
                outcome = OUTCOME_REQUEST_CHANGES
            else:
                outcome = OUTCOME_INCONCLUSIVE
        else:  # all_accept_or_3_of_4_no_blockers
            if reject == len(review_list) and reject > 0:
                outcome = OUTCOME_QUARANTINE
            elif accept >= 3 and changes == 0:
                # >= 3 accept and no blocking / change requests -> advance
                outcome = OUTCOME_ADVANCE
            elif changes > 0:
                outcome = OUTCOME_REQUEST_CHANGES
            else:
                outcome = OUTCOME_INCONCLUSIVE

    return ReviewSummary(
        finding_id=finding_id,
        version=version,
        mode=mode,
        quorum_policy=quorum_policy,
        reviewer_count=len(review_list),
        accept_count=accept,
        reject_count=reject,
        request_changes_count=changes,
        blocking_issues=[
            (
                f"scope_safety=unsafe:{r.reviewer_agent_id}"
                if r.scope_safety == "unsafe"
                else (
                    f"validity=invalid:{r.reviewer_agent_id}"
                    if r.validity == "invalid"
                    else (
                        f"severity_consistency=inconsistent:{r.reviewer_agent_id}"
                        if r.severity_consistency == "inconsistent"
                        else f"unknown:{r.reviewer_agent_id}"
                    )
                )
            )
            for r in blocking
        ],
        outcome=outcome,
        has_dispute=dispute_count > 0,
        dispute_count=dispute_count,
        reviews=tuple(review_list),
    )


async def record_summary(
    conn: aiosqlite.Connection, summary: ReviewSummary
) -> None:
    record = summary.to_record()
    await conn.execute(
        "INSERT INTO finding_review_summaries("
        "id, schema_version, finding_id, version, mode, quorum_policy, reviewer_count, "
        "accept_count, reject_count, request_changes_count, blocking_issues, outcome, "
        "has_dispute, dispute_count, created_at"
        ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            record["id"],
            record["schema_version"],
            record["finding_id"],
            record["version"],
            record["mode"],
            record["quorum_policy"],
            record["reviewer_count"],
            record["accept_count"],
            record["reject_count"],
            record["request_changes_count"],
            record["blocking_issues"],
            record["outcome"],
            record["has_dispute"],
            record["dispute_count"],
            record["created_at"],
        ),
    )
    await conn.commit()


async def get_summary(
    conn: aiosqlite.Connection, *, finding_id: str, version: int, mode: str
) -> ReviewSummary | None:
    cur = await conn.execute(
        "SELECT * FROM finding_review_summaries "
        "WHERE finding_id = ? AND version = ? AND mode = ?",
        (finding_id, version, mode),
    )
    row = await cur.fetchone()
    if row is None:
        return None
    blocking = json.loads(row["blocking_issues"]) if row["blocking_issues"] else []
    return ReviewSummary(
        finding_id=row["finding_id"],
        version=row["version"],
        mode=row["mode"],
        quorum_policy=row["quorum_policy"],
        reviewer_count=row["reviewer_count"],
        accept_count=row["accept_count"],
        reject_count=row["reject_count"],
        request_changes_count=row["request_changes_count"],
        blocking_issues=blocking,
        outcome=row["outcome"],
        has_dispute=bool(row["has_dispute"]),
        dispute_count=row["dispute_count"],
        created_at=datetime.fromisoformat(row["created_at"]),
    )


# ---- deletion safeguard -------------------------------------------------


@dataclass(frozen=True)
class DeletionVerdict:
    original_conclusion: str  # "incorrect"
    original_review_id: str
    dispute_review_id: str | None
    eligible: bool
    reason: str


def evaluate_deletion(
    reviews: Iterable[schema.Review], *, original_conclusion: str = "incorrect"
) -> DeletionVerdict:
    """Two-review deletion rule (spec §10.5).

    A finding may be tombstoned only when *both*:

    1. the original review concluded ``incorrect``, and
    2. an independent dispute review also concluded ``incorrect``.

    Returns a :class:`DeletionVerdict` describing whether the dual
    confirmation is in place. The actual tombstone call is still
    gated by a human approval token.
    """
    if original_conclusion != "incorrect":
        return DeletionVerdict(
            original_conclusion=original_conclusion,
            original_review_id="",
            dispute_review_id=None,
            eligible=False,
            reason="original review did not conclude 'incorrect'",
        )
    originals = [
        r
        for r in reviews
        if not r.is_dispute
        and r.verdict == schema.ReviewVerdict.REJECT
        and r.validity == "invalid"
    ]
    disputes = [
        r
        for r in reviews
        if r.is_dispute
        and r.verdict == schema.ReviewVerdict.REJECT
        and r.validity == "invalid"
    ]
    if not originals:
        return DeletionVerdict(
            original_conclusion=original_conclusion,
            original_review_id="",
            dispute_review_id=None,
            eligible=False,
            reason="no original 'incorrect' review found",
        )
    if not disputes:
        return DeletionVerdict(
            original_conclusion=original_conclusion,
            original_review_id=originals[0].id,
            dispute_review_id=None,
            eligible=False,
            reason="dispute review required for tombstone",
        )
    return DeletionVerdict(
        original_conclusion=original_conclusion,
        original_review_id=originals[0].id,
        dispute_review_id=disputes[0].id,
        eligible=True,
        reason="dual confirmation (original + dispute) — eligible for tombstone",
    )


__all__ = [
    "DeletionVerdict",
    "OUTCOME_ADVANCE",
    "OUTCOME_INCONCLUSIVE",
    "OUTCOME_QUARANTINE",
    "OUTCOME_REQUEST_CHANGES",
    "QUORUM_ALL_ACCEPT",
    "QUORUM_ALL_ACCEPT_OR_3_OF_4_NO_BLOCKERS",
    "ReviewError",
    "ReviewSummary",
    "KNOWN_QUORUM_POLICIES",
    "compute_summary",
    "evaluate_deletion",
    "get_summary",
    "insert",
    "list_all_for_finding",
    "list_for_finding_version",
    "record_summary",
]
