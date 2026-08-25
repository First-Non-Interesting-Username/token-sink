"""Global kill switch.

When active, the orchestrator must:

* refuse to start new network-bound tasks,
* cancel any in-flight tasks that are about to issue network calls,
* surface a banner in the UI (later phases).

The flag is stored in the ``kill_switch`` table with a single row
(id = 1) so a database read is the source of truth across processes.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import aiosqlite

from mavr.observability.logging import get_logger

log = get_logger(__name__)

_ROW_ID = 1


@dataclass(frozen=True)
class KillSwitchState:
    active: bool
    reason: str
    activated_by: str | None
    activated_at: datetime | None


def _now() -> datetime:
    return datetime.now(UTC)


def _row_to_state(row: aiosqlite.Row | None) -> KillSwitchState:
    if row is None:
        return KillSwitchState(
            active=False, reason="", activated_by=None, activated_at=None
        )
    return KillSwitchState(
        active=bool(row["is_active"]),
        reason=row["reason"] or "",
        activated_by=row["activated_by"],
        activated_at=datetime.fromisoformat(row["activated_at"]) if row["activated_at"] else None,
    )


async def _ensure_row(conn: aiosqlite.Connection) -> None:
    await conn.execute(
        "INSERT OR IGNORE INTO kill_switch(id, is_active, reason) VALUES (1, 0, '')"
    )


async def get(conn: aiosqlite.Connection) -> KillSwitchState:
    await _ensure_row(conn)
    cur = await conn.execute("SELECT * FROM kill_switch WHERE id = ?", (_ROW_ID,))
    return _row_to_state(await cur.fetchone())


async def activate(
    conn: aiosqlite.Connection, *, reason: str, activated_by: str
) -> KillSwitchState:
    await _ensure_row(conn)
    now = _now()
    await conn.execute(
        "UPDATE kill_switch SET is_active = 1, reason = ?, activated_by = ?, activated_at = ? "
        "WHERE id = ?",
        (reason, activated_by, now.isoformat(), _ROW_ID),
    )
    await conn.commit()
    log.warning("kill_switch_activated", reason=reason, activated_by=activated_by)
    return KillSwitchState(
        active=True, reason=reason, activated_by=activated_by, activated_at=now
    )


async def deactivate(
    conn: aiosqlite.Connection, *, deactivated_by: str
) -> KillSwitchState:
    await _ensure_row(conn)
    await conn.execute(
        "UPDATE kill_switch SET is_active = 0, reason = '', activated_by = NULL, activated_at = NULL "
        "WHERE id = ?",
        (_ROW_ID,),
    )
    await conn.commit()
    log.info("kill_switch_deactivated", deactivated_by=deactivated_by)
    return KillSwitchState(
        active=False, reason="", activated_by=None, activated_at=None
    )


def banner(state: KillSwitchState) -> str:
    if not state.active:
        return ""
    when = state.activated_at.isoformat() if state.activated_at else "unknown"
    return (
        f"KILL SWITCH ACTIVE (since {when}, by {state.activated_by or 'unknown'}): "
        f"{state.reason}. New network actions are refused."
    )


def is_network_action_allowed(state: KillSwitchState, action: dict[str, Any] | None = None) -> bool:
    """Return True if a network-bound action is allowed right now."""
    return not state.active
