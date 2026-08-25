"""Search and extraction subagent helpers.

These are thin wrappers that make the search / extraction subsystem
available to other agents through the runtime's normal task +
subagent flow. A parent agent calls :func:`search_subagent` or
:func:`extraction_subagent`; the helper:

1. Mints a child :class:`schema.Agent` with role
   :data:`SEARCH_ROLE` or :data:`EXTRACTION_ROLE`.
2. Spawns a :class:`mavr.orchestrator.queue` task for it.
3. Returns the child + task so the caller can wait on completion.

The actual handler that processes the task lives in this module
(:class:`SearchAgentHandler`, :class:`ExtractionAgentHandler`).
They are :class:`mavr.orchestrator.runtime.AgentHandler` implementers
and can be plugged into :func:`mavr.orchestrator.runtime.execute`.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

from mavr.agents import identity as identity_mod
from mavr.config.loader import AppConfig
from mavr.observability.logging import get_logger
from mavr.orchestrator import runtime
from mavr.orchestrator.failures import PolicyViolation
from mavr.schemas import entities as schema
from mavr.search import engine as search_engine
from mavr.search import evidence as evidence_mod
from mavr.search import extract as extract_mod
from mavr.search import safety as search_safety
from mavr.search.safety import scope_allows_unsafe_networking
from mavr.storage.artifacts import ArtifactStore
from mavr.storage.database import Database

log = get_logger(__name__)


#: The agent role used for search subagents. Alias for
#: :data:`schema.AgentRole.SEARCH`.
SEARCH_ROLE: schema.AgentRole = schema.AgentRole.SEARCH
#: The agent role used for extraction subagents. Alias for
#: :data:`schema.AgentRole.EXTRACTION`.
EXTRACTION_ROLE: schema.AgentRole = schema.AgentRole.EXTRACTION


# ---- request types --------------------------------------------------------


@dataclass(frozen=True)
class SearchRequest:
    """A description of a search the parent agent wants done."""

    query: str
    top_n: int | None = None
    safe_search: str | None = None
    use_cache: bool = True


@dataclass(frozen=True)
class ExtractionRequest:
    """A description of an extraction the parent agent wants done."""

    url: str
    jina_allowlist: tuple[str, ...] = field(default_factory=tuple)
    max_bytes: int | None = None
    timeout_seconds: int | None = None


# ---- handlers -------------------------------------------------------------


class SearchAgentHandler:
    """Implements the :class:`runtime.AgentHandler` protocol for search."""

    def __init__(self, engine: search_engine.SearchEngine) -> None:
        self._engine = engine

    async def __call__(
        self,
        task: schema.Task,
        ctx: runtime.RuntimeContext,
    ) -> dict[str, Any]:
        request = task.payload.get("request") or {}
        query = str(request.get("query") or "").strip()
        if not query:
            raise search_engine.SearchConfigError("query missing in task payload")

        campaign, scope = await _load_campaign_and_scope(ctx.db, task.campaign_id)

        outcome = self._engine.search(
            query,
            campaign=campaign,
            scope=scope,
            top_n=request.get("top_n"),
            safe_search=request.get("safe_search"),
            use_cache=bool(request.get("use_cache", True)),
        )

        rows = await search_engine.persist_results(
            outcome,
            campaign_id=task.campaign_id,
            task_id=task.id,
            conn=ctx.db,
        )
        return {
            "query": outcome.query,
            "engine": outcome.engine,
            "safe_search": outcome.safe_search,
            "cache_hit": outcome.cache_hit,
            "error": outcome.error,
            "result_ids": [r.id for r in rows],
            "urls": [r.url for r in rows],
            "in_scope_urls": [r.url for r in rows if r.in_scope],
            "result_count": len(rows),
        }

    @staticmethod
    def output_schema() -> type[schema.BaseModel] | None:
        return None


class ExtractionAgentHandler:
    """Implements the :class:`runtime.AgentHandler` protocol for extraction."""

    def __init__(
        self,
        *,
        artifacts: ArtifactStore,
        options: extract_mod.ExtractionOptions | None = None,
    ) -> None:
        self._artifacts = artifacts
        self._options = options or extract_mod.ExtractionOptions()

    async def __call__(
        self,
        task: schema.Task,
        ctx: runtime.RuntimeContext,
    ) -> dict[str, Any]:
        request = task.payload.get("request") or {}
        url = str(request.get("url") or "").strip()
        if not url:
            raise extract_mod.ExtractionError("url missing in task payload")

        campaign, scope = await _load_campaign_and_scope(ctx.db, task.campaign_id)
        allow_unsafe = scope_allows_unsafe_networking(scope)
        if not url.startswith(("http://", "https://")):
            raise extract_mod.ExtractionError("only http(s) URLs are supported")
        # The handler charges the network budget for the fetch.
        ctx.charge_network()

        opts = self._options
        if request.get("max_bytes") is not None:
            opts = extract_mod.ExtractionOptions(
                max_bytes=int(request["max_bytes"]),
                max_redirects=opts.max_redirects,
                timeout_seconds=opts.timeout_seconds,
                user_agent=opts.user_agent,
                jina_allowlist=opts.jina_allowlist,
                allow_unsafe_networking=allow_unsafe,
                jina_endpoint=opts.jina_endpoint,
            )
        if request.get("timeout_seconds") is not None:
            opts = extract_mod.ExtractionOptions(
                max_bytes=opts.max_bytes,
                max_redirects=opts.max_redirects,
                timeout_seconds=int(request["timeout_seconds"]),
                user_agent=opts.user_agent,
                jina_allowlist=opts.jina_allowlist,
                allow_unsafe_networking=allow_unsafe,
                jina_endpoint=opts.jina_endpoint,
            )
        jina_allowlist = tuple(request.get("jina_allowlist") or opts.jina_allowlist)
        opts = extract_mod.ExtractionOptions(
            max_bytes=opts.max_bytes,
            max_redirects=opts.max_redirects,
            timeout_seconds=opts.timeout_seconds,
            user_agent=opts.user_agent,
            jina_allowlist=jina_allowlist,
            allow_unsafe_networking=allow_unsafe,
            jina_endpoint=opts.jina_endpoint,
        )

        try:
            result = extract_mod.fetch(
                url, options=opts, allow_unsafe_networking=allow_unsafe
            )
        except (
            search_safety.SSRFBlocked,
            search_safety.UnsafeScheme,
            search_safety.PathTraversalError,
        ) as exc:
            # Re-raise as a PolicyViolation so the runtime classifies
            # it as a policy failure (no retries, no escape from
            # quarantine).
            raise PolicyViolation(f"target refused by safety policy: {exc}") from exc
        except extract_mod.BackendUnavailable as exc:
            raise PolicyViolation(f"extraction backend unavailable: {exc}") from exc
        extracted, evidence, sanitized = extract_mod.store_extraction(
            result,
            campaign_id=task.campaign_id,
            task_id=task.id,
            artifacts=self._artifacts,
        )
        await evidence_mod.record_evidence(ctx.db, evidence=evidence)
        await evidence_mod.record_extracted_source(ctx.db, source=extracted)

        return {
            "evidence_id": evidence.id,
            "extracted_source_id": extracted.id,
            "content_hash": evidence.content_hash,
            "byte_length": evidence.byte_length,
            "content_type": evidence.content_type,
            "extractor": result.extractor,
            "removed_tag_count": sanitized.removed_tag_count,
            "removed_attr_count": sanitized.removed_attr_count,
            "title": sanitized.title,
            "raw_artifact_id": evidence.raw_artifact_id,
            "extracted_artifact_id": evidence.extracted_artifact_id,
        }

    @staticmethod
    def output_schema() -> type[schema.BaseModel] | None:
        return None


# ---- subagent spawners ----------------------------------------------------


async def search_subagent(
    db: Any,
    *,
    parent: schema.Agent,
    request: SearchRequest,
    config: AppConfig | None = None,
) -> tuple[schema.Agent, schema.Task]:
    """Spawn a child search agent and enqueue a search task for it.

    ``db`` may be either an :class:`mavr.storage.database.Database`
    (recommended) or a raw :class:`aiosqlite.Connection`. The
    function manages its own transactions either way: when given a
    :class:`Database`, it borrows a connection; when given a raw
    connection, it commits at the end and the caller must NOT
    already hold the connection inside an open transaction.
    """
    sub_req = runtime.SubagentRequest(
        objective=f"search: {request.query}",
        role=SEARCH_ROLE,
        allowed_tools=("search",),
        scope={"query": request.query, "top_n": request.top_n},
        completion_criteria="results persisted; in-scope URLs returned",
        metadata={"query": request.query},
    )
    payload = json.dumps({
        "agent_id": "placeholder",        # patched in below
        "parent_agent_id": parent.id,
        "role": SEARCH_ROLE.value,
        "request": {
            "query": request.query,
            "top_n": request.top_n,
            "safe_search": request.safe_search,
            "use_cache": request.use_cache,
        },
        "completion_criteria": "results persisted; in-scope URLs returned",
    }, ensure_ascii=False)
    if isinstance(db, Database):
        async with db.acquire() as conn:
            child, task = await runtime.spawn_subagent(
                conn, parent=parent, request=sub_req
            )
            payload_dict = json.loads(payload)
            payload_dict["agent_id"] = child.id
            payload = json.dumps(payload_dict, ensure_ascii=False)
            await conn.execute(
                "UPDATE tasks SET payload = ? WHERE id = ?", (payload, task.id)
            )
            await conn.commit()
            cur = await conn.execute(
                "SELECT * FROM tasks WHERE id = ?", (task.id,)
            )
            row = await cur.fetchone()
    else:
        child, task = await runtime.spawn_subagent(
            db, parent=parent, request=sub_req
        )
        payload_dict = json.loads(payload)
        payload_dict["agent_id"] = child.id
        payload = json.dumps(payload_dict, ensure_ascii=False)
        await db.execute(
            "UPDATE tasks SET payload = ? WHERE id = ?", (payload, task.id)
        )
        await db.commit()
        cur = await db.execute(
            "SELECT * FROM tasks WHERE id = ?", (task.id,)
        )
        row = await cur.fetchone()
    return child, _row_to_task(row)


async def extraction_subagent(
    db: Any,
    *,
    parent: schema.Agent,
    request: ExtractionRequest,
    config: AppConfig | None = None,
) -> tuple[schema.Agent, schema.Task]:
    """Spawn a child extraction agent and enqueue an extraction task.

    See :func:`search_subagent` for the ``db`` parameter contract.
    """
    sub_req = runtime.SubagentRequest(
        objective=f"extract: {request.url}",
        role=EXTRACTION_ROLE,
        allowed_tools=("extract",),
        scope={"url": request.url},
        completion_criteria="evidence + extracted source persisted",
    )
    payload = json.dumps({
        "agent_id": "placeholder",
        "parent_agent_id": parent.id,
        "role": EXTRACTION_ROLE.value,
        "request": {
            "url": request.url,
            "jina_allowlist": list(request.jina_allowlist),
            "max_bytes": request.max_bytes,
            "timeout_seconds": request.timeout_seconds,
        },
        "completion_criteria": "evidence + extracted source persisted",
    }, ensure_ascii=False)
    if isinstance(db, Database):
        async with db.acquire() as conn:
            child, task = await runtime.spawn_subagent(
                conn, parent=parent, request=sub_req
            )
            payload_dict = json.loads(payload)
            payload_dict["agent_id"] = child.id
            payload = json.dumps(payload_dict, ensure_ascii=False)
            await conn.execute(
                "UPDATE tasks SET payload = ? WHERE id = ?", (payload, task.id)
            )
            await conn.commit()
            cur = await conn.execute(
                "SELECT * FROM tasks WHERE id = ?", (task.id,)
            )
            row = await cur.fetchone()
    else:
        child, task = await runtime.spawn_subagent(
            db, parent=parent, request=sub_req
        )
        payload_dict = json.loads(payload)
        payload_dict["agent_id"] = child.id
        payload = json.dumps(payload_dict, ensure_ascii=False)
        await db.execute(
            "UPDATE tasks SET payload = ? WHERE id = ?", (payload, task.id)
        )
        await db.commit()
        cur = await db.execute(
            "SELECT * FROM tasks WHERE id = ?", (task.id,)
        )
        row = await cur.fetchone()
    return child, _row_to_task(row)


def _row_to_task(row: Any) -> schema.Task:
    import json
    from datetime import datetime

    payload = json.loads(row["payload"]) if row["payload"] else {}
    def _iso(name: str) -> Any:
        v = row[name]
        return datetime.fromisoformat(v) if v else None

    return schema.Task(
        id=row["id"],
        schema_version=row["schema_version"],
        campaign_id=row["campaign_id"],
        parent_task_id=row["parent_task_id"],
        kind=schema.TaskKind(row["kind"]),
        status=schema.TaskStatus(row["status"]),
        priority=row["priority"],
        payload=payload,
        result=json.loads(row["result"]) if row["result"] else None,
        error=row["error"],
        idempotency_key=row["idempotency_key"],
        attempt=row["attempt"],
        max_attempts=row["max_attempts"],
        lease_owner=row["lease_owner"],
        lease_expires_at=_iso("lease_expires_at"),
        lease_heartbeat_at=_iso("lease_heartbeat_at"),
        started_at=_iso("started_at"),
        finished_at=_iso("finished_at"),
        created_at=datetime.fromisoformat(row["created_at"]),
        updated_at=datetime.fromisoformat(row["updated_at"]),
    )


# ---- helpers --------------------------------------------------------------


def _serialize_payload(payload: dict[str, Any]) -> str:
    return json.dumps(payload, ensure_ascii=False)


async def _load_campaign_and_scope(
    db: Any, campaign_id: str
) -> tuple[schema.Campaign, schema.ScopePolicy]:
    """Look up the campaign + scope policy for a task. Centralized so
    the handler doesn't have to repeat the SQL.
    """
    cur = await db.execute(
        "SELECT * FROM campaigns WHERE id = ?", (campaign_id,)
    )
    row = await cur.fetchone()
    if row is None:
        raise extract_mod.ExtractionError(
            f"campaign {campaign_id} not found"
        )
    target_spec = row["target_spec"]
    if isinstance(target_spec, str):
        try:
            target_spec = json.loads(target_spec) if target_spec else {}
        except json.JSONDecodeError:
            target_spec = {}
    config_snapshot = row["config_snapshot"]
    if isinstance(config_snapshot, str):
        try:
            config_snapshot = json.loads(config_snapshot) if config_snapshot else {}
        except json.JSONDecodeError:
            config_snapshot = {}
    campaign = schema.Campaign.model_validate({
        "id": row["id"],
        "schema_version": row["schema_version"],
        "name": row["name"],
        "description": row["description"],
        "target_spec": target_spec,
        "state": row["state"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
        "started_at": row["started_at"],
        "finished_at": row["finished_at"],
        "human_approved": bool(row["human_approved"]),
        "duration_hours": int(row["duration_hours"]),
        "token_budget": int(row["token_budget"]),
        "tool_budget": int(row["tool_budget"]),
        "config_snapshot": config_snapshot,
    })
    cur = await db.execute(
        "SELECT * FROM scope_policies WHERE campaign_id = ? ORDER BY created_at DESC LIMIT 1",
        (campaign_id,),
    )
    sp_row = await cur.fetchone()
    if sp_row is None:
        # No policy yet: synthesize a default-deny one. This matches
        # the spec's "scope before action" rule — the agent cannot
        # proceed without a policy.
        import uuid as _uuid
        from datetime import UTC, datetime

        now = datetime.now(UTC)
        scope = schema.ScopePolicy(
            id=str(_uuid.uuid4()),
            campaign_id=campaign_id,
            created_at=now,
            updated_at=now,
            allowed_targets=[],
            allowed_methods=["GET", "HEAD"],
            action_allowlist=[],
            rate_limit_per_minute=60,
            active_testing=False,
            explicit_unsafe_networking=False,
            human_approved=False,
        )
        return campaign, scope
    scope = schema.ScopePolicy.model_validate({
        "id": sp_row["id"],
        "schema_version": sp_row["schema_version"],
        "campaign_id": sp_row["campaign_id"],
        "allowed_targets": json.loads(sp_row["allowed_targets"]) if sp_row["allowed_targets"] else [],
        "allowed_methods": json.loads(sp_row["allowed_methods"]) if sp_row["allowed_methods"] else ["GET", "HEAD"],
        "action_allowlist": json.loads(sp_row["action_allowlist"]) if sp_row["action_allowlist"] else [],
        "rate_limit_per_minute": int(sp_row["rate_limit_per_minute"]),
        "active_testing": bool(sp_row["active_testing"]),
        "explicit_unsafe_networking": bool(sp_row["explicit_unsafe_networking"]),
        "human_approved": bool(sp_row["human_approved"]),
        "created_at": sp_row["created_at"],
        "updated_at": sp_row["updated_at"],
    })
    return campaign, scope


def _row_to_json(row: Any, fields: list[str]) -> str:
    out: dict[str, Any] = {}
    for f in fields:
        v = row[f]
        # SQLite stores booleans as 0/1; map to JSON bools.
        if f in {"human_approved", "active_testing", "explicit_unsafe_networking"}:
            out[f] = bool(v)
        elif f in {"duration_hours", "rate_limit_per_minute", "token_budget", "tool_budget"}:
            out[f] = int(v)
        else:
            out[f] = v
    return json.dumps(out, ensure_ascii=False)


# Suppress unused imports in slim configs.
_ = (urlparse, identity_mod)
