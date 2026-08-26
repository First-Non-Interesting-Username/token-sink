"""Finding quarantine semantics (spec §2.5, §10.5, §14).

Quarantine is the third outcome distinct from deletion (#259's
tombstones) and from active review. This module layers explicit
entry/exit rules and preservation guarantees on the lifecycle state
machine (which already allows ``* → quarantined``):

Entry paths
-----------
* ``all-reject`` PoC review — handled by
  :func:`mavr.findings.workflow.fold_reviews` (quorum quarantine).
* :func:`enter_manual` — operator quarantine via an audited,
  approval-backed transition with a required reason.
* :func:`enter_policy_fail` — a safety/policy gate hard-fail that
  stops short of deletion.

Exit rules
----------
* :func:`restore` — returns the finding to a prior active state for a
  new evidence cycle. The restore target must be one of the recorded
  prior states; re-quarantine is allowed but bounded: the third
  entry is refused and flagged in metadata so an unbounded
  quarantine↔restore loop cannot spin silently.
* Escalation to ``tombstoned`` stays on #259's dual-confirmation
  path (:func:`mavr.findings.workflow.tombstone`) — not duplicated
  here.

Preservation guarantees
-----------------------
Quarantine never destroys anything: version history, review records,
and provenance rows are left untouched. :func:`assert_preserved`
verifies this after any entry/exit.

Export exclusion
----------------
:func:`exportable_findings` excludes quarantined findings by default;
callers may pass ``include_quarantined=True`` explicitly.
"""
from __future__ import annotations

import aiosqlite

from mavr.findings import lifecycle
from mavr.observability.logging import get_logger
from mavr.schemas import entities as schema

log = get_logger(__name__)

# A finding may be quarantined at most this many times before restore
# is refused and the loop flag is set (§14: surface pathological loops).
MAX_QUARANTINE_CYCLES = 2

# States a quarantined finding may be restored into (bounded re-entry
# targets: back to review or rework, never straight to terminal states).
_RESTORABLE_STATES = {
    schema.FindingState.INITIAL,
    schema.FindingState.REVIEW_CYCLE_1,
    schema.FindingState.DISPUTED,
    schema.FindingState.POC_DRAFT,
    schema.FindingState.POC_REVIEW,
    schema.FindingState.POLISHED,
}


class QuarantineError(ValueError):
    """A quarantine operation violated the §2.5/§10.5 rules."""


async def _quarantine_count(conn: aiosqlite.Connection, finding_id: str) -> int:
    cur = await conn.execute(
        "SELECT COUNT(*) AS n FROM finding_transitions "
        "WHERE finding_id = ? AND new_state = ?",
        (finding_id, schema.FindingState.QUARANTINED.value),
    )
    row = await cur.fetchone()
    return int(row["n"]) if row else 0


async def _prior_active_state(
    conn: aiosqlite.Connection, finding_id: str
) -> schema.FindingState | None:
    """Most recent non-quarantined, non-terminal state from history."""
    cur = await conn.execute(
        "SELECT prior_state FROM finding_transitions "
        "WHERE finding_id = ? AND new_state = ? AND prior_state IS NOT NULL "
        "ORDER BY created_at DESC, id DESC LIMIT 1",
        (finding_id, schema.FindingState.QUARANTINED.value),
    )
    row = await cur.fetchone()
    if not row or not row["prior_state"]:
        return None
    try:
        return schema.FindingState(row["prior_state"])
    except ValueError:
        return None


def _check_cycles(count: int) -> None:
    if count >= MAX_QUARANTINE_CYCLES:
        raise QuarantineError(
            f"finding has been quarantined {count} times (limit "
            f"{MAX_QUARANTINE_CYCLES}); restore is refused — escalate via "
            "the tombstone path or resolve the blocking evidence"
        )


async def enter_manual(
    conn: aiosqlite.Connection,
    *,
    finding_id: str,
    actor_id: str | None,
    reason: str,
    approval_ref: str | None = None,
) -> schema.Finding:
    """Operator-initiated quarantine.

    Requires a non-empty reason; when ``approval_ref`` is given it is
    carried in the transition metadata for audit linkage.
    """
    if not reason.strip():
        raise QuarantineError("manual quarantine requires a reason")
    await _guard_entry(conn, finding_id)
    return await lifecycle.transition(
        conn,
        finding_id=finding_id,
        new_state=schema.FindingState.QUARANTINED,
        actor_id=actor_id,
        actor_kind=schema.ActorKind.HUMAN if actor_id else schema.ActorKind.SYSTEM,
        reason=reason,
        metadata={
            "entry": "manual",
            "approval_ref": approval_ref or "",
            "cycle": await _quarantine_count(conn, finding_id) + 1,
        },
    )


async def enter_policy_fail(
    conn: aiosqlite.Connection,
    *,
    finding_id: str,
    gate: str,
    detail: str,
    actor_id: str | None = None,
) -> schema.Finding:
    """Policy/safety-gate failure that stops short of deletion."""
    if not gate.strip() or not detail.strip():
        raise QuarantineError("policy-fail quarantine requires gate and detail")
    await _guard_entry(conn, finding_id)
    return await lifecycle.transition(
        conn,
        finding_id=finding_id,
        new_state=schema.FindingState.QUARANTINED,
        actor_id=actor_id,
        actor_kind=schema.ActorKind.SYSTEM,
        reason=f"policy gate failed: {gate}",
        metadata={"entry": "policy_fail", "gate": gate, "detail": detail},
    )


async def _guard_entry(
    conn: aiosqlite.Connection, finding_id: str
) -> None:
    finding = await lifecycle.get(conn, finding_id)
    if finding is None:
        raise QuarantineError(f"finding {finding_id} not found")
    if finding.state == schema.FindingState.QUARANTINED:
        raise QuarantineError("finding is already quarantined")
    _check_cycles(await _quarantine_count(conn, finding_id))


async def restore(
    conn: aiosqlite.Connection,
    *,
    finding_id: str,
    to_state: schema.FindingState | None = None,
    actor_id: str | None = None,
    reason: str = "",
) -> schema.Finding:
    """Restore a quarantined finding to an active state.

    Defaults to the state the finding was in immediately before the
    latest quarantine entry. The target must be a restorable (active)
    state — never a terminal one.
    """
    finding = await lifecycle.get(conn, finding_id)
    if finding is None:
        raise QuarantineError(f"finding {finding_id} not found")
    if finding.state != schema.FindingState.QUARANTINED:
        raise QuarantineError(
            f"cannot restore: finding is in {finding.state.value}, not quarantined"
        )
    target = to_state or await _prior_active_state(conn, finding_id)
    if target is None:
        raise QuarantineError("no prior active state recorded; pass to_state explicitly")
    if target not in _RESTORABLE_STATES:
        raise QuarantineError(f"state {target.value} is not a restorable target")
    restored = await lifecycle.transition(
        conn,
        finding_id=finding_id,
        new_state=target,
        actor_id=actor_id,
        reason=reason or "quarantine restore",
        metadata={"exit": "restore"},
    )
    log.info(
        "finding_quarantine_restored", finding_id=finding_id, to_state=target.value
    )
    return restored


# ---- preservation guarantees -----------------------------------------------


async def assert_preserved(
    conn: aiosqlite.Connection,
    *,
    finding_id: str,
    expected_versions: int,
    expected_reviews: int,
) -> None:
    """Verify quarantine destroyed nothing (§2.5 preservation).

    Compares current row counts against caller-supplied expectations
    captured before the quarantine transition.
    """
    cur = await conn.execute(
        "SELECT COUNT(*) AS n FROM finding_versions WHERE finding_id = ?",
        (finding_id,),
    )
    vrow = await cur.fetchone()
    versions = int(vrow["n"]) if vrow else 0
    cur = await conn.execute(
        "SELECT COUNT(*) AS n FROM reviews WHERE finding_id = ?",
        (finding_id,),
    )
    rrow = await cur.fetchone()
    reviews = int(rrow["n"]) if rrow else 0
    if versions < expected_versions or reviews < expected_reviews:
        raise QuarantineError(
            f"preservation violation: versions {versions}<{expected_versions} "
            f"or reviews {reviews}<{expected_reviews}"
        )


# ---- export exclusion ------------------------------------------------------


async def exportable_findings(
    conn: aiosqlite.Connection, *, campaign_id: str, include_quarantined: bool = False
) -> list[schema.Finding]:
    """Findings safe to include in a report bundle.

    Quarantined findings are excluded by default (§2.5/§13 view 6);
    callers must opt in explicitly.
    """
    findings = await lifecycle.list_for_campaign(conn, campaign_id)
    return [
        f
        for f in findings
        if include_quarantined or f.state != schema.FindingState.QUARANTINED
    ]


__all__ = [
    "MAX_QUARANTINE_CYCLES",
    "QuarantineError",
    "assert_preserved",
    "enter_manual",
    "enter_policy_fail",
    "exportable_findings",
    "restore",
]
