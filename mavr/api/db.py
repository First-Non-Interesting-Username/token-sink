"""Campaign / finding / task / scope-policy DB helpers used by the API.

These helpers keep the API layer free of inline SQL and centralize the
UUID + schema-version bookkeeping. They are read/write thin wrappers
that do not enforce business rules beyond what the schema itself does;
business rules (free-only routing, active-testing approval, etc.) live
in higher layers.
"""
from __future__ import annotations

import json
from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from mavr.storage.database import Database


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


async def create_campaign(
    db: Database,
    *,
    name: str,
    description: str = "",
    target_spec: dict[str, Any] | None = None,
    duration_hours: int = 24,
    token_budget: int = 0,
    tool_budget: int = 0,
    config_snapshot: dict[str, Any] | None = None,
    state: str = "draft",
) -> str:
    cid = str(uuid4())
    spec = target_spec or {}
    snapshot = config_snapshot or {}
    from mavr.schemas import entities as schema

    await db.execute(
        "INSERT INTO campaigns("
        "id, schema_version, name, description, target_spec, state, "
        "created_at, updated_at, human_approved, duration_hours, "
        "token_budget, tool_budget, config_snapshot"
        ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            cid,
            schema.SCHEMA_VERSION,
            name,
            description,
            json.dumps(spec, ensure_ascii=False),
            state,
            _now_iso(),
            _now_iso(),
            0,
            int(duration_hours),
            int(token_budget),
            int(tool_budget),
            json.dumps(snapshot, ensure_ascii=False),
        ),
    )
    return cid


async def list_campaigns(db: Database, *, limit: int = 200) -> list[dict[str, Any]]:
    async with db.acquire() as conn:
        cur = await conn.execute(
            "SELECT id, name, description, state, created_at, updated_at, "
            "started_at, finished_at, human_approved, duration_hours "
            "FROM campaigns ORDER BY created_at DESC LIMIT ?",
            (int(limit),),
        )
        return [dict(r) for r in await cur.fetchall()]


async def get_campaign(db: Database, campaign_id: str) -> dict[str, Any] | None:
    async with db.acquire() as conn:
        cur = await conn.execute("SELECT * FROM campaigns WHERE id = ?", (campaign_id,))
        row = await cur.fetchone()
        return dict(row) if row else None


async def set_campaign_state(
    db: Database, campaign_id: str, state: str
) -> bool:
    async with db.acquire() as conn:
        cur = await conn.execute(
            "UPDATE campaigns SET state = ?, updated_at = ? WHERE id = ?",
            (state, _now_iso(), campaign_id),
        )
        return cur.rowcount > 0


async def upsert_scope_policy(
    db: Database,
    *,
    campaign_id: str,
    allowed_targets: Iterable[str],
    allowed_methods: Iterable[str],
    action_allowlist: Iterable[str],
    rate_limit_per_minute: int = 60,
    active_testing: bool = False,
    explicit_unsafe_networking: bool = False,
) -> str:
    """Create or update the scope policy for ``campaign_id``."""
    from mavr.schemas import entities as schema

    now = _now_iso()
    async with db.acquire() as conn:
        cur = await conn.execute(
            "SELECT id FROM scope_policies WHERE campaign_id = ?", (campaign_id,)
        )
        existing = await cur.fetchone()
        sid = existing["id"] if existing else str(uuid4())
        if existing:
            await conn.execute(
                "UPDATE scope_policies SET allowed_targets = ?, allowed_methods = ?, "
                "action_allowlist = ?, rate_limit_per_minute = ?, active_testing = ?, "
                "explicit_unsafe_networking = ?, updated_at = ? WHERE id = ?",
                (
                    json.dumps(list(allowed_targets), ensure_ascii=False),
                    json.dumps(list(allowed_methods), ensure_ascii=False),
                    json.dumps(list(action_allowlist), ensure_ascii=False),
                    int(rate_limit_per_minute),
                    1 if active_testing else 0,
                    1 if explicit_unsafe_networking else 0,
                    now,
                    sid,
                ),
            )
        else:
            await conn.execute(
                "INSERT INTO scope_policies("
                "id, schema_version, campaign_id, allowed_targets, allowed_methods, "
                "action_allowlist, rate_limit_per_minute, active_testing, "
                "explicit_unsafe_networking, human_approved, created_at, updated_at"
                ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    sid,
                    schema.SCHEMA_VERSION,
                    campaign_id,
                    json.dumps(list(allowed_targets), ensure_ascii=False),
                    json.dumps(list(allowed_methods), ensure_ascii=False),
                    json.dumps(list(action_allowlist), ensure_ascii=False),
                    int(rate_limit_per_minute),
                    1 if active_testing else 0,
                    1 if explicit_unsafe_networking else 0,
                    0,
                    now,
                    now,
                ),
            )
        await conn.commit()
    return sid


async def get_scope_policy(db: Database, campaign_id: str) -> dict[str, Any] | None:
    async with db.acquire() as conn:
        cur = await conn.execute(
            "SELECT * FROM scope_policies WHERE campaign_id = ?", (campaign_id,)
        )
        row = await cur.fetchone()
        if row is None:
            return None
        out = dict(row)
        for key in ("allowed_targets", "allowed_methods", "action_allowlist"):
            try:
                out[key] = json.loads(out[key]) if out.get(key) else []
            except (TypeError, ValueError):
                out[key] = []
        return out


async def list_agents(
    db: Database, *, campaign_id: str | None = None, status: str | None = None, limit: int = 200
) -> list[dict[str, Any]]:
    clauses: list[str] = []
    params: list[Any] = []
    if campaign_id:
        clauses.append("campaign_id = ?")
        params.append(campaign_id)
    if status:
        clauses.append("status = ?")
        params.append(status)
    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
    params.append(int(limit))
    async with db.acquire() as conn:
        cur = await conn.execute(
            "SELECT id, parent_id, role, status, campaign_id, task_id, created_at, "
            "updated_at, budget_tokens, tokens_used FROM agents" + where + " ORDER BY created_at DESC LIMIT ?",
            params,
        )
        return [dict(r) for r in await cur.fetchall()]


async def list_tasks(
    db: Database, *, campaign_id: str | None = None, status: str | None = None, limit: int = 200
) -> list[dict[str, Any]]:
    clauses: list[str] = []
    params: list[Any] = []
    if campaign_id:
        clauses.append("campaign_id = ?")
        params.append(campaign_id)
    if status:
        clauses.append("status = ?")
        params.append(status)
    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
    params.append(int(limit))
    async with db.acquire() as conn:
        cur = await conn.execute(
            "SELECT id, campaign_id, parent_task_id, kind, status, priority, "
            "attempt, max_attempts, created_at, updated_at, started_at, finished_at, error "
            "FROM tasks" + where + " ORDER BY created_at DESC LIMIT ?",
            params,
        )
        return [dict(r) for r in await cur.fetchall()]


async def list_findings(
    db: Database, *, campaign_id: str | None = None, state: str | None = None, limit: int = 200
) -> list[dict[str, Any]]:
    clauses: list[str] = []
    params: list[Any] = []
    if campaign_id:
        clauses.append("campaign_id = ?")
        params.append(campaign_id)
    if state:
        clauses.append("state = ?")
        params.append(state)
    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
    params.append(int(limit))
    async with db.acquire() as conn:
        cur = await conn.execute(
            "SELECT id, campaign_id, title, state, severity, confidence, "
            "current_version, tombstoned, created_at, updated_at "
            "FROM findings" + where + " ORDER BY updated_at DESC LIMIT ?",
            params,
        )
        return [dict(r) for r in await cur.fetchall()]


async def get_finding(db: Database, finding_id: str) -> dict[str, Any] | None:
    async with db.acquire() as conn:
        cur = await conn.execute("SELECT * FROM findings WHERE id = ?", (finding_id,))
        row = await cur.fetchone()
        return dict(row) if row else None


async def list_audit(
    db: Database, *, limit: int = 200, campaign_id: str | None = None
) -> list[dict[str, Any]]:
    clauses: list[str] = []
    params: list[Any] = []
    if campaign_id:
        clauses.append("subject_kind = 'campaign' AND subject_id = ?")
        params.append(campaign_id)
    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
    params.append(int(limit))
    async with db.acquire() as conn:
        cur = await conn.execute(
            "SELECT id, event_id, actor_id, actor_kind, category, subject_kind, "
            "subject_id, prior_state, new_state, reason, created_at "
            "FROM audit_events" + where + " ORDER BY id DESC LIMIT ?",
            params,
        )
        return [dict(r) for r in await cur.fetchall()]


async def get_kill_switch(db: Database) -> dict[str, Any]:
    from mavr.orchestrator import killswitch as ks_mod

    async with db.acquire() as conn:
        await ks_mod._ensure_row(conn)  # noqa: SLF001 — internal helper
        state = await ks_mod.get(conn)
    return {
        "id": 1,
        "is_active": 1 if state.active else 0,
        "reason": state.reason,
        "activated_by": state.activated_by,
        "activated_at": state.activated_at.isoformat() if state.activated_at else None,
    }


async def set_kill_switch(db: Database, *, active: bool, reason: str, by: str) -> dict[str, Any]:
    from mavr.orchestrator import killswitch as ks_mod

    async with db.acquire() as conn:
        await ks_mod._ensure_row(conn)  # noqa: SLF001 — internal helper
        if active:
            await ks_mod.activate(conn, reason=reason, activated_by=by)
        else:
            await ks_mod.deactivate(conn, deactivated_by=by)
    return await get_kill_switch(db)


__all__ = [
    "create_campaign",
    "get_campaign",
    "get_finding",
    "get_kill_switch",
    "get_scope_policy",
    "list_agents",
    "list_audit",
    "list_campaigns",
    "list_findings",
    "list_tasks",
    "set_campaign_state",
    "set_kill_switch",
    "upsert_scope_policy",
]
