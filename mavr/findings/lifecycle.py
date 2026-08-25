"""Finding lifecycle state machine (spec §10).

States (in order, with side-branches):

    initial_findings
      -> review_cycle_1
        -> validated
          -> impact_analysis -> poc_draft -> poc_review
            -> polished_report -> final_review -> vulnerabilities
        -> disputed (must be re-opened or tombstoned by 2 reviews)
    quarantined
    tombstoned

Every transition writes a row in ``finding_transitions`` (append-only)
plus an :class:`AuditEvent` with prior_state / new_state / reason /
actor_id. Each state has an associated lease; the orchestrator must
hold the lease to mutate the state.
"""
from __future__ import annotations

import json
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import aiosqlite

from mavr.observability.logging import get_logger
from mavr.orchestrator import audit
from mavr.schemas import entities as schema

log = get_logger(__name__)


class FindingStateError(RuntimeError):
    pass


ALLOWED_TRANSITIONS: dict[schema.FindingState, set[schema.FindingState]] = {
    schema.FindingState.INITIAL: {
        schema.FindingState.REVIEW_CYCLE_1,
        schema.FindingState.QUARANTINED,
        schema.FindingState.TOMBSTONED,
    },
    schema.FindingState.REVIEW_CYCLE_1: {
        schema.FindingState.VALIDATED,
        schema.FindingState.DISPUTED,
        schema.FindingState.QUARANTINED,
        schema.FindingState.TOMBSTONED,
    },
    schema.FindingState.VALIDATED: {
        schema.FindingState.IMPACT,
        schema.FindingState.QUARANTINED,
        schema.FindingState.TOMBSTONED,
    },
    schema.FindingState.DISPUTED: {
        schema.FindingState.REVIEW_CYCLE_1,
        schema.FindingState.TOMBSTONED,
    },
    schema.FindingState.IMPACT: {
        schema.FindingState.POC_DRAFT,
        schema.FindingState.QUARANTINED,
        schema.FindingState.TOMBSTONED,
    },
    schema.FindingState.POC_DRAFT: {
        schema.FindingState.POC_REVIEW,
        schema.FindingState.QUARANTINED,
        schema.FindingState.TOMBSTONED,
    },
    schema.FindingState.POC_REVIEW: {
        schema.FindingState.POLISHED,
        schema.FindingState.QUARANTINED,
        schema.FindingState.POC_DRAFT,  # rework loop
        schema.FindingState.TOMBSTONED,
    },
    schema.FindingState.POLISHED: {
        schema.FindingState.FINAL_REVIEW,
        schema.FindingState.QUARANTINED,
        schema.FindingState.TOMBSTONED,
    },
    schema.FindingState.FINAL_REVIEW: {
        schema.FindingState.VULNERABILITY,
        schema.FindingState.POLISHED,  # rework
        schema.FindingState.QUARANTINED,
        schema.FindingState.TOMBSTONED,
    },
    schema.FindingState.VULNERABILITY: set(),  # terminal
    schema.FindingState.QUARANTINED: {
        schema.FindingState.TOMBSTONED,
    },
    schema.FindingState.TOMBSTONED: set(),  # terminal
}


ARTIFACT_BY_STATE: dict[schema.FindingState, str] = {
    schema.FindingState.INITIAL: "initial_findings.md",
    schema.FindingState.REVIEW_CYCLE_1: "review_cycle_1.md",
    schema.FindingState.IMPACT: "impact_analysis.md",
    schema.FindingState.POC_DRAFT: "poc_draft.md",
    schema.FindingState.POLISHED: "polished_report.md",
}


def can_transition(prior: schema.FindingState, new: schema.FindingState) -> bool:
    return new in ALLOWED_TRANSITIONS.get(prior, set())


def _now() -> datetime:
    return datetime.now(UTC)


def _row_to_finding(row: aiosqlite.Row) -> schema.Finding:
    return schema.Finding(
        id=row["id"],
        schema_version=row["schema_version"],
        campaign_id=row["campaign_id"],
        title=row["title"],
        state=schema.FindingState(row["state"]),
        severity=schema.Severity(row["severity"]) if row["severity"] else None,
        confidence=row["confidence"],
        current_version=row["current_version"],
        tombstoned=bool(row["tombstoned"]),
        tombstone_reason=row["tombstone_reason"],
        created_at=datetime.fromisoformat(row["created_at"]),
        updated_at=datetime.fromisoformat(row["updated_at"]),
    )


async def insert(
    conn: aiosqlite.Connection,
    *,
    campaign_id: str,
    title: str,
    severity: schema.Severity | None = None,
    confidence: str | None = None,
) -> schema.Finding:
    fid = str(uuid4())
    now_iso = _now().isoformat()
    await conn.execute(
        "INSERT INTO findings("
        "id, schema_version, campaign_id, title, state, severity, confidence, "
        "current_version, tombstoned, created_at, updated_at"
        ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?)",
        (
            fid,
            schema.SCHEMA_VERSION,
            campaign_id,
            title,
            schema.FindingState.INITIAL.value,
            severity.value if severity else None,
            confidence,
            1,
            now_iso,
            now_iso,
        ),
    )
    await _record_transition(
        conn,
        finding_id=fid,
        prior_state=None,
        new_state=schema.FindingState.INITIAL,
        reason="finding created",
        actor_id=None,
        actor_kind=schema.ActorKind.SYSTEM,
    )
    await conn.commit()
    row = await (await conn.execute("SELECT * FROM findings WHERE id = ?", (fid,))).fetchone()
    assert row is not None
    return _row_to_finding(row)


async def get(conn: aiosqlite.Connection, finding_id: str) -> schema.Finding | None:
    cur = await conn.execute("SELECT * FROM findings WHERE id = ?", (finding_id,))
    row = await cur.fetchone()
    return _row_to_finding(row) if row else None


async def list_for_campaign(
    conn: aiosqlite.Connection, campaign_id: str
) -> list[schema.Finding]:
    cur = await conn.execute(
        "SELECT * FROM findings WHERE campaign_id = ? ORDER BY created_at",
        (campaign_id,),
    )
    return [_row_to_finding(r) for r in await cur.fetchall()]


async def list_by_state(
    conn: aiosqlite.Connection, state: schema.FindingState
) -> list[schema.Finding]:
    cur = await conn.execute(
        "SELECT * FROM findings WHERE state = ? AND tombstoned = 0 ORDER BY updated_at",
        (state.value,),
    )
    return [_row_to_finding(r) for r in await cur.fetchall()]


# ---- transitions ----------------------------------------------------------


async def transition(
    conn: aiosqlite.Connection,
    *,
    finding_id: str,
    new_state: schema.FindingState,
    actor_id: str | None,
    actor_kind: schema.ActorKind = schema.ActorKind.AGENT,
    reason: str = "",
    metadata: dict[str, Any] | None = None,
    force: bool = False,
    lease_token: str | None = None,
) -> schema.Finding:
    cur = await conn.execute("SELECT * FROM findings WHERE id = ?", (finding_id,))
    row = await cur.fetchone()
    if row is None:
        raise FindingStateError(f"finding {finding_id} not found")
    finding = _row_to_finding(row)
    if finding.state == new_state:
        return finding
    if not force and not can_transition(finding.state, new_state):
        raise FindingStateError(
            f"illegal finding transition: {finding.state.value} -> {new_state.value}"
        )
    now_iso = _now().isoformat()
    bump_version = new_state in {
        schema.FindingState.IMPACT,
        schema.FindingState.POC_DRAFT,
        schema.FindingState.POLISHED,
    }
    if bump_version:
        await conn.execute(
            "UPDATE findings SET state = ?, updated_at = ?, current_version = current_version + 1 "
            "WHERE id = ?",
            (new_state.value, now_iso, finding_id),
        )
    else:
        await conn.execute(
            "UPDATE findings SET state = ?, updated_at = ? WHERE id = ?",
            (new_state.value, now_iso, finding_id),
        )
    if new_state == schema.FindingState.TOMBSTONED:
        await conn.execute(
            "UPDATE findings SET tombstoned = 1, tombstone_reason = ? WHERE id = ?",
            (reason, finding_id),
        )
    await _record_transition(
        conn,
        finding_id=finding_id,
        prior_state=finding.state,
        new_state=new_state,
        reason=reason,
        actor_id=actor_id,
        actor_kind=actor_kind,
        metadata=metadata or {},
    )
    await conn.commit()
    finding.state = new_state
    finding.updated_at = _now()
    if bump_version:
        finding.current_version += 1
    if new_state == schema.FindingState.TOMBSTONED:
        finding.tombstoned = True
        finding.tombstone_reason = reason
    return finding


async def _record_transition(
    conn: aiosqlite.Connection,
    *,
    finding_id: str,
    prior_state: schema.FindingState | None,
    new_state: schema.FindingState,
    reason: str,
    actor_id: str | None,
    actor_kind: schema.ActorKind,
    metadata: dict[str, Any] | None = None,
) -> None:
    transition_id = str(uuid4())
    now_iso = _now().isoformat()
    await conn.execute(
        "INSERT INTO finding_transitions("
        "id, finding_id, prior_state, new_state, reason, actor_id, actor_kind, "
        "metadata, created_at"
        ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            transition_id,
            finding_id,
            prior_state.value if prior_state else None,
            new_state.value,
            reason,
            actor_id,
            actor_kind.value,
            json.dumps(metadata or {}, ensure_ascii=False),
            now_iso,
        ),
    )
    await audit.record(
        conn,
        actor_id=actor_id,
        actor_kind=actor_kind,
        category=schema.AuditCategory.STATE_TRANSITION,
        subject_kind="finding",
        subject_id=finding_id,
        prior_state=prior_state.value if prior_state else None,
        new_state=new_state.value,
        reason=reason,
        metadata=metadata or {},
    )


async def history(
    conn: aiosqlite.Connection, finding_id: str
) -> list[dict[str, Any]]:
    cur = await conn.execute(
        "SELECT * FROM finding_transitions WHERE finding_id = ? ORDER BY created_at",
        (finding_id,),
    )
    out: list[dict[str, Any]] = []
    for row in await cur.fetchall():
        out.append(
            {
                "id": row["id"],
                "prior_state": row["prior_state"],
                "new_state": row["new_state"],
                "reason": row["reason"],
                "actor_id": row["actor_id"],
                "actor_kind": row["actor_kind"],
                "metadata": json.loads(row["metadata"]) if row["metadata"] else {},
                "created_at": row["created_at"],
            }
        )
    return out


# ---- leases ---------------------------------------------------------------


@dataclass(frozen=True)
class FindingLease:
    finding_id: str
    owner: str
    token: str
    expires_at: datetime


def _new_lease_token() -> str:
    return f"flease_{secrets.token_urlsafe(16)}"


def _iso(dt: datetime) -> str:
    return dt.astimezone(UTC).isoformat()


async def _active_lease(
    conn: aiosqlite.Connection, finding_id: str
) -> aiosqlite.Row | None:
    cur = await conn.execute(
        "SELECT id, owner, token, expires_at FROM finding_leases "
        "WHERE finding_id = ? AND released_at IS NULL "
        "ORDER BY acquired_at DESC LIMIT 1",
        (finding_id,),
    )
    return await cur.fetchone()


async def lease(
    conn: aiosqlite.Connection, *, finding_id: str, owner: str, ttl_seconds: int = 300
) -> FindingLease | None:
    """Acquire an exclusive lease on a finding's state machine.

    Leases are stored in the dedicated ``finding_leases`` table (see
    migration 0003). Re-leasing is allowed for the same owner; a
    different owner can only acquire if no live lease exists or the
    live lease has expired.
    """
    now = _now()
    live = await _active_lease(conn, finding_id)
    if live is not None:
        live_expires = datetime.fromisoformat(live["expires_at"])
        if live_expires > now and live["owner"] != owner:
            return None
    token = _new_lease_token()
    expires_at = datetime.fromtimestamp(now.timestamp() + ttl_seconds, tz=UTC)
    lease_id = str(uuid4())
    await conn.execute(
        "INSERT INTO finding_leases("
        "id, finding_id, owner, token, acquired_at, expires_at, released_at"
        ") VALUES (?, ?, ?, ?, ?, ?, NULL)",
        (lease_id, finding_id, owner, token, _iso(now), _iso(expires_at)),
    )
    await conn.commit()
    return FindingLease(finding_id=finding_id, owner=owner, token=token, expires_at=expires_at)


async def release_lease(
    conn: aiosqlite.Connection, *, finding_id: str, owner: str
) -> bool:
    """Release every live lease for ``owner`` on this finding.

    The previous design mutated a single transition row's metadata and
    could clobber (or be clobbered by) a concurrent
    :func:`transition`. Leases now live in their own table, so
    ownership is decoupled from the append-only transition log.
    """
    now_iso = _iso(_now())
    cur = await conn.execute(
        "UPDATE finding_leases SET released_at = ? "
        "WHERE finding_id = ? AND owner = ? AND released_at IS NULL",
        (now_iso, finding_id, owner),
    )
    await conn.commit()
    return cur.rowcount > 0


# ---- artifacts ------------------------------------------------------------


def artifact_path_for(finding: schema.Finding, state: schema.FindingState) -> str:
    """Return the relative path under ``artifacts/<campaign>/<finding>/``."""
    name = ARTIFACT_BY_STATE.get(state)
    if name is None:
        raise FindingStateError(f"no artifact filename for state {state.value}")
    return f"{finding.campaign_id}/{finding.id}/{name}"
