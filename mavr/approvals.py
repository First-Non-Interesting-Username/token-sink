"""Approvals subsystem (spec §10, §17).

A human approval is a session-scoped token that authorizes a single
class of privileged action (active testing, submission, scope change,
deletion). The token is minted via the CLI or UI, expires after a
short TTL, and is consumed (or revoked) on use. Every privileged
action records the approval id in the audit log so we can prove
authorization after the fact.

Approval rows live in the ``approvals`` table from migration 0005.
The helpers in this module are the only writers; reading is done
through :func:`get_by_token` and :func:`list_for_campaign`.
"""
from __future__ import annotations

import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import aiosqlite

from mavr.observability.logging import get_logger
from mavr.orchestrator import audit
from mavr.schemas import entities as schema

log = get_logger(__name__)


class ApprovalError(RuntimeError):
    """Raised when an approval token is invalid, expired, or already used."""


APPROVAL_KINDS: frozenset[str] = frozenset(
    {"active_testing", "submission", "scope_change", "deletion"}
)


@dataclass(frozen=True)
class Approval:
    id: str
    token: str
    action: str
    actor: str
    reason: str
    campaign_id: str | None
    finding_id: str | None
    expires_at: datetime
    consumed_at: datetime | None
    revoked_at: datetime | None
    created_at: datetime


def _now() -> datetime:
    return datetime.now(UTC)


def _iso(dt: datetime) -> str:
    return dt.astimezone(UTC).isoformat()


def _row_to_approval(row: aiosqlite.Row) -> Approval:
    return Approval(
        id=row["id"],
        token=row["token"],
        action=row["action"],
        actor=row["actor"],
        reason=row["reason"] or "",
        campaign_id=row["campaign_id"],
        finding_id=row["finding_id"],
        expires_at=datetime.fromisoformat(row["expires_at"]),
        consumed_at=datetime.fromisoformat(row["consumed_at"])
        if row["consumed_at"]
        else None,
        revoked_at=datetime.fromisoformat(row["revoked_at"]) if row["revoked_at"] else None,
        created_at=datetime.fromisoformat(row["created_at"]),
    )


def mint_token() -> str:
    """Generate a fresh, URL-safe approval token."""
    return f"appr_{secrets.token_urlsafe(24)}"


async def create(
    conn: aiosqlite.Connection,
    *,
    action: str,
    actor: str,
    reason: str = "",
    campaign_id: str | None = None,
    finding_id: str | None = None,
    ttl_seconds: int = 900,
) -> Approval:
    if action not in APPROVAL_KINDS:
        raise ApprovalError(f"unknown approval action: {action!r}")
    if ttl_seconds < 1 or ttl_seconds > 24 * 3600:
        raise ApprovalError("ttl_seconds must be in [1, 86400]")
    aid = str(uuid4())
    token = mint_token()
    now = _now()
    expires = now + timedelta(seconds=ttl_seconds)
    await conn.execute(
        "INSERT INTO approvals("
        "id, schema_version, token, action, campaign_id, finding_id, actor, reason, "
        "expires_at, consumed_at, revoked_at, created_at"
        ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, ?)",
        (
            aid,
            schema.SCHEMA_VERSION,
            token,
            action,
            campaign_id,
            finding_id,
            actor,
            reason,
            _iso(expires),
            _iso(now),
        ),
    )
    await conn.commit()
    return Approval(
        id=aid,
        token=token,
        action=action,
        actor=actor,
        reason=reason,
        campaign_id=campaign_id,
        finding_id=finding_id,
        expires_at=expires,
        consumed_at=None,
        revoked_at=None,
        created_at=now,
    )


async def get_by_token(
    conn: aiosqlite.Connection, token: str
) -> Approval | None:
    cur = await conn.execute(
        "SELECT * FROM approvals WHERE token = ?", (token,)
    )
    row = await cur.fetchone()
    return _row_to_approval(row) if row else None


async def list_for_campaign(
    conn: aiosqlite.Connection, campaign_id: str
) -> list[Approval]:
    cur = await conn.execute(
        "SELECT * FROM approvals WHERE campaign_id = ? ORDER BY created_at DESC",
        (campaign_id,),
    )
    return [_row_to_approval(r) for r in await cur.fetchall()]


async def consume(
    conn: aiosqlite.Connection, *, token: str, expected_action: str
) -> Approval:
    """Validate ``token`` and mark it consumed.

    Raises :class:`ApprovalError` if the token is unknown, expired,
    revoked, already consumed, or issued for a different action.
    """
    approval = await get_by_token(conn, token)
    if approval is None:
        raise ApprovalError("unknown approval token")
    if approval.revoked_at is not None:
        raise ApprovalError("approval token has been revoked")
    if approval.consumed_at is not None:
        raise ApprovalError("approval token already consumed")
    if approval.expires_at <= _now():
        raise ApprovalError("approval token has expired")
    if approval.action != expected_action:
        raise ApprovalError(
            f"approval token is for {approval.action!r}, not {expected_action!r}"
        )
    await conn.execute(
        "UPDATE approvals SET consumed_at = ? WHERE id = ?",
        (_iso(_now()), approval.id),
    )
    await audit.record(
        conn,
        actor_id=None,
        actor_kind=schema.ActorKind.HUMAN,
        category=schema.AuditCategory.APPROVAL,
        subject_kind="approval",
        subject_id=approval.id,
        prior_state="issued",
        new_state="consumed",
        reason=f"action={approval.action}",
        metadata={
            "action": approval.action,
            "actor": approval.actor,
            "campaign_id": approval.campaign_id,
            "finding_id": approval.finding_id,
        },
    )
    await conn.commit()
    return Approval(
        id=approval.id,
        token=approval.token,
        action=approval.action,
        actor=approval.actor,
        reason=approval.reason,
        campaign_id=approval.campaign_id,
        finding_id=approval.finding_id,
        expires_at=approval.expires_at,
        consumed_at=_now(),
        revoked_at=approval.revoked_at,
        created_at=approval.created_at,
    )


async def revoke(
    conn: aiosqlite.Connection, *, token: str, reason: str = ""
) -> bool:
    cur = await conn.execute(
        "UPDATE approvals SET revoked_at = ? WHERE token = ? AND revoked_at IS NULL",
        (_iso(_now()), token),
    )
    if cur.rowcount:
        await audit.record(
            conn,
            actor_id=None,
            actor_kind=schema.ActorKind.HUMAN,
            category=schema.AuditCategory.APPROVAL,
            subject_kind="approval",
            subject_id=None,
            prior_state="issued",
            new_state="revoked",
            reason=reason or "token revoked",
            metadata={"token": token[-6:]},
        )
    await conn.commit()
    return cur.rowcount > 0


__all__ = [
    "APPROVAL_KINDS",
    "Approval",
    "ApprovalError",
    "consume",
    "create",
    "get_by_token",
    "list_for_campaign",
    "mint_token",
    "revoke",
]
