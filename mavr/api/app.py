"""FastAPI application: state, routes, SSE, UI mount."""
from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import (
    HTMLResponse,
    JSONResponse,
    PlainTextResponse,
    Response,
    StreamingResponse,
)
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from mavr import approvals as approvals_mod
from mavr.api import db as api_db
from mavr.api import sse
from mavr.api.approval_gate import ApprovalGate
from mavr.api.auth import (
    TOKEN_PREFIX,
    enforce_localhost,
    new_bearer_token,
    require_bearer,
)
from mavr.api.schemas import (
    ApprovalCreateRequest,
    CampaignNewRequest,
    EventPublishRequest,
    KillSwitchRequest,
    MetricPointRequest,
    ProviderTestRequest,
    ScopePolicyRequest,
)
from mavr.config.loader import AppConfig
from mavr.observability.context import current_correlation
from mavr.observability.events import EventBus
from mavr.observability.logging import get_logger
from mavr.observability.metrics import MetricsStore
from mavr.storage.database import Database, apply_migrations

log = get_logger(__name__)

UI_DIR = Path(__file__).resolve().parent.parent / "ui"
TEMPLATES_DIR = UI_DIR / "templates"
STATIC_DIR = UI_DIR / "static"


@dataclass
class AppState:
    """Process-wide state shared by every request handler."""

    config: AppConfig
    db: Database
    events: EventBus
    metrics: MetricsStore
    approvals: ApprovalGate
    token: str
    bind_host: str
    allow_lan: bool
    human_approved: bool
    sse_hub: sse.SSEHub


class App:
    """The MAVR web application.

    Construct via :func:`build_app`; do not instantiate directly.
    """

    def __init__(self, state: AppState, fastapi: FastAPI) -> None:
        self.state = state
        self.app = fastapi

    def bearer_token(self) -> str:
        return self.state.token

    def url(self) -> str:
        return f"http://{self.state.bind_host}:{self.state.config.server.port}"


def _bind_hosts() -> tuple[str, ...]:
    return ("127.0.0.1", "::1", "localhost")


def _verify_bind_host(host: str, *, allow_lan: bool, human_approved: bool) -> None:
    """Refuse wildcard binds unless both flags are set."""
    wildcard = host in {"0.0.0.0", "::", ""}
    if wildcard and not (allow_lan and human_approved):
        raise RuntimeError(
            "refusing to bind on a non-loopback address without --allow-lan "
            "and an explicit human_approved flag",
        )


async def _ensure_migrations(db: Database) -> None:
    await apply_migrations(db, "up")


def _make_templates() -> Jinja2Templates:
    return Jinja2Templates(directory=str(TEMPLATES_DIR))


def build_app(
    *,
    config: AppConfig,
    db: Database,
    bind_host: str | None = None,
    allow_lan: bool = False,
    human_approved: bool = False,
    token: str | None = None,
) -> App:
    """Construct an :class:`App` ready to be served by uvicorn."""
    _verify_bind_host(
        bind_host or config.server.host,
        allow_lan=allow_lan,
        human_approved=human_approved,
    )
    if bind_host is None:
        bind_host = config.server.host

    token = token or new_bearer_token()
    if not token.startswith(TOKEN_PREFIX):
        token = f"{TOKEN_PREFIX}{token}"

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        await _ensure_migrations(db)
        log.info("api.startup", host=bind_host, port=config.server.port)
        try:
            yield
        finally:
            log.info("api.shutdown")

    fastapi_app = FastAPI(
        title="MAVR Local API",
        version="0.1.0",
        docs_url="/api/docs",
        redoc_url=None,
        openapi_url="/api/openapi.json",
        lifespan=lifespan,
    )

    events = EventBus(db)
    metrics = MetricsStore(db)
    approvals = ApprovalGate(db, metrics=metrics)
    sse_hub = sse.SSEHub(db, events=events)

    state = AppState(
        config=config,
        db=db,
        events=events,
        metrics=metrics,
        approvals=approvals,
        token=token,
        bind_host=bind_host,
        allow_lan=allow_lan,
        human_approved=human_approved,
        sse_hub=sse_hub,
    )

    fastapi_app.state.mavr = state

    # The auth dependency is parameterized with the token at startup.
    auth_dep = require_bearer(token)

    def _guard(request: Request) -> None:
        enforce_localhost(
            bind_host,
            allow_lan=allow_lan,
            human_approved=human_approved,
            client_host=request.client.host if request.client else None,
        )

    # ---- routes ---------------------------------------------------------

    @fastapi_app.middleware("http")
    async def _loopback_guard(request: Request, call_next):  # type: ignore[no-redef]
        if request.url.path.startswith("/api/") or request.url.path == "/":
            try:
                _guard(request)
            except HTTPException as exc:
                return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)
        return await call_next(request)

    api = APIRouter(prefix="/api")

    @api.get("/health")
    async def health(_: Any = Depends(auth_dep)) -> dict[str, Any]:
        return {
            "status": "ok",
            "version": "0.1.0",
            "config": {
                "host": state.bind_host,
                "port": state.config.server.port,
                "allow_lan": state.allow_lan,
            },
        }

    @api.get("/correlation")
    async def correlation(_: Any = Depends(auth_dep)) -> dict[str, str]:
        return current_correlation()

    # ---- campaigns -----------------------------------------------------

    @api.get("/campaigns")
    async def list_campaigns_endpoint(
        limit: int = Query(50, ge=1, le=500), _: Any = Depends(auth_dep)
    ) -> list[dict[str, Any]]:
        return await api_db.list_campaigns(state.db, limit=limit)

    @api.post("/campaigns", status_code=201)
    async def create_campaign_endpoint(
        req: CampaignNewRequest, _: Any = Depends(auth_dep)
    ) -> dict[str, Any]:
        cid = await api_db.create_campaign(
            state.db,
            name=req.name,
            description=req.description,
            target_spec=req.target_spec,
            duration_hours=req.duration_hours,
            token_budget=req.token_budget,
            tool_budget=req.tool_budget,
            config_snapshot=req.config_snapshot,
        )
        await state.events.publish(
            event_type="campaign.created",
            campaign_id=cid,
            payload={"name": req.name},
        )
        return {"id": cid}

    @api.get("/campaigns/{campaign_id}")
    async def get_campaign_endpoint(
        campaign_id: str, _: Any = Depends(auth_dep)
    ) -> dict[str, Any]:
        campaign = await api_db.get_campaign(state.db, campaign_id)
        if campaign is None:
            raise HTTPException(status_code=404, detail="unknown campaign")
        scope = await api_db.get_scope_policy(state.db, campaign_id)
        return {"campaign": campaign, "scope": scope}

    @api.post("/campaigns/{campaign_id}/scope")
    async def upsert_scope_endpoint(
        campaign_id: str,
        req: ScopePolicyRequest,
        _auth: Any = Depends(auth_dep),
    ) -> dict[str, Any]:
        if req.campaign_id != campaign_id:
            raise HTTPException(status_code=400, detail="campaign_id mismatch")
        campaign = await api_db.get_campaign(state.db, campaign_id)
        if campaign is None:
            raise HTTPException(status_code=404, detail="unknown campaign")
        sid = await api_db.upsert_scope_policy(
            state.db,
            campaign_id=campaign_id,
            allowed_targets=req.allowed_targets,
            allowed_methods=req.allowed_methods,
            action_allowlist=req.action_allowlist,
            rate_limit_per_minute=req.rate_limit_per_minute,
            active_testing=req.active_testing,
            explicit_unsafe_networking=req.explicit_unsafe_networking,
        )
        await state.events.publish(
            event_type="scope.updated",
            campaign_id=campaign_id,
            payload={
                "scope_policy_id": sid,
                "active_testing": req.active_testing,
                "explicit_unsafe_networking": req.explicit_unsafe_networking,
            },
        )
        return {"scope_policy_id": sid}

    @api.post("/campaigns/{campaign_id}/export")
    async def export_campaign_endpoint(
        campaign_id: str, _: Any = Depends(auth_dep)
    ) -> dict[str, Any]:
        from mavr.observability.bundle import export_run_bundle

        campaign = await api_db.get_campaign(state.db, campaign_id)
        if campaign is None:
            raise HTTPException(status_code=404, detail="unknown campaign")
        out_dir = Path(state.config.storage.artifact_dir).expanduser() / "bundles"
        out_dir.mkdir(parents=True, exist_ok=True)
        out_path = out_dir / f"{campaign_id}.zip"
        result = await export_run_bundle(
            state.db,
            campaign_id=campaign_id,
            output_path=out_path,
            config_snapshot=state.config,
        )
        await state.events.publish(
            event_type="campaign.exported",
            campaign_id=campaign_id,
            payload={"size_bytes": result.size_bytes, "entries": result.entry_count},
        )
        return {
            "path": str(result.path),
            "size_bytes": result.size_bytes,
            "entry_count": result.entry_count,
        }

    # ---- agents / tasks / findings ------------------------------------

    @api.get("/agents")
    async def list_agents_endpoint(
        campaign_id: str | None = Query(None),
        status_filter: str | None = Query(None, alias="status"),
        limit: int = Query(50, ge=1, le=500),
        _: Any = Depends(auth_dep),
    ) -> list[dict[str, Any]]:
        return await api_db.list_agents(
            state.db, campaign_id=campaign_id, status=status_filter, limit=limit
        )

    @api.get("/tasks")
    async def list_tasks_endpoint(
        campaign_id: str | None = Query(None),
        status_filter: str | None = Query(None, alias="status"),
        limit: int = Query(50, ge=1, le=500),
        _: Any = Depends(auth_dep),
    ) -> list[dict[str, Any]]:
        return await api_db.list_tasks(
            state.db, campaign_id=campaign_id, status=status_filter, limit=limit
        )

    @api.get("/findings")
    async def list_findings_endpoint(
        campaign_id: str | None = Query(None),
        state_filter: str | None = Query(None, alias="state"),
        limit: int = Query(50, ge=1, le=500),
        _: Any = Depends(auth_dep),
    ) -> list[dict[str, Any]]:
        return await api_db.list_findings(
            state.db, campaign_id=campaign_id, state=state_filter, limit=limit
        )

    @api.get("/findings/{finding_id}")
    async def get_finding_endpoint(
        finding_id: str, _: Any = Depends(auth_dep)
    ) -> dict[str, Any]:
        finding = await api_db.get_finding(state.db, finding_id)
        if finding is None:
            raise HTTPException(status_code=404, detail="unknown finding")
        return finding

    # ---- approvals ----------------------------------------------------

    @api.post("/approvals", status_code=201)
    async def create_approval_endpoint(
        req: ApprovalCreateRequest, _: Any = Depends(auth_dep)
    ) -> dict[str, Any]:
        async with state.db.acquire() as conn:
            approval = await approvals_mod.create(
                conn,
                action=req.action,
                actor=req.actor,
                reason=req.reason,
                campaign_id=req.campaign_id,
                finding_id=req.finding_id,
                ttl_seconds=req.ttl_seconds,
            )
        await state.events.publish(
            event_type="approval.created",
            campaign_id=req.campaign_id,
            finding_id=req.finding_id,
            payload={"action": approval.action, "actor": approval.actor},
        )
        return {
            "id": approval.id,
            "token": approval.token,
            "action": approval.action,
            "actor": approval.actor,
            "expires_at": approval.expires_at.isoformat(),
        }

    @api.get("/approvals")
    async def list_approvals_endpoint(
        campaign_id: str | None = Query(None),
        _: Any = Depends(auth_dep),
    ) -> list[dict[str, Any]]:
        async with state.db.acquire() as conn:
            if campaign_id:
                rows = await approvals_mod.list_for_campaign(conn, campaign_id)
            else:
                cur = await conn.execute(
                    "SELECT * FROM approvals ORDER BY created_at DESC LIMIT 200"
                )
                rows = [approvals_mod._row_to_approval(r) for r in await cur.fetchall()]
        return [
            {
                "id": r.id,
                "action": r.action,
                "actor": r.actor,
                "reason": r.reason,
                "campaign_id": r.campaign_id,
                "finding_id": r.finding_id,
                "expires_at": r.expires_at.isoformat(),
                "consumed_at": r.consumed_at.isoformat() if r.consumed_at else None,
                "revoked_at": r.revoked_at.isoformat() if r.revoked_at else None,
                "created_at": r.created_at.isoformat(),
            }
            for r in rows
        ]

    @api.post("/approvals/revoke")
    async def revoke_approval_endpoint(
        token: str = Query(...), _: Any = Depends(auth_dep)
    ) -> dict[str, Any]:
        async with state.db.acquire() as conn:
            ok = await approvals_mod.revoke(conn, token=token)
        return {"revoked": ok}

    # ---- providers / models ------------------------------------------

    @api.get("/providers")
    async def list_providers_endpoint(_: Any = Depends(auth_dep)) -> list[dict[str, Any]]:
        from mavr.providers.registry import ProviderRegistry

        registry = ProviderRegistry.default()
        try:
            out: list[dict[str, Any]] = []
            for s in registry.list():
                out.append(
                    {
                        "provider_id": s.provider_id,
                        "kind": s.kind,
                        "free": s.free,
                        "auth_status": s.auth_status,
                        "model_count": s.model_count,
                        "display_name": s.display_name,
                    }
                )
            return out
        finally:
            await registry.aclose()

    @api.post("/providers/test")
    async def test_provider_endpoint(
        req: ProviderTestRequest, _: Any = Depends(auth_dep)
    ) -> dict[str, Any]:
        from mavr.providers.registry import ProviderRegistry

        registry = ProviderRegistry.default()
        try:
            if not registry.has(req.provider_id):
                raise HTTPException(status_code=404, detail="unknown provider")
            report = await registry.health(req.provider_id)
            return {
                "ok": report.ok,
                "provider_id": req.provider_id,
                "auth_status": report.auth_status,
                "latency_ms": report.latency_ms,
                "detail": report.detail,
            }
        finally:
            await registry.aclose()

    # ---- kill switch / policy ---------------------------------------

    @api.get("/kill_switch")
    async def get_kill_switch_endpoint(_: Any = Depends(auth_dep)) -> dict[str, Any]:
        return await api_db.get_kill_switch(state.db)

    @api.post("/kill_switch")
    async def set_kill_switch_endpoint(
        req: KillSwitchRequest, _: Any = Depends(auth_dep)
    ) -> dict[str, Any]:
        result = await api_db.set_kill_switch(
            state.db, active=req.active, reason=req.reason, by=req.by
        )
        await state.events.publish(
            event_type="kill_switch.changed",
            payload={"active": req.active, "reason": req.reason, "by": req.by},
            severity="warning" if req.active else "info",
        )
        return result

    # ---- audit ------------------------------------------------------

    @api.get("/audit")
    async def list_audit_endpoint(
        campaign_id: str | None = Query(None),
        limit: int = Query(50, ge=1, le=500),
        _: Any = Depends(auth_dep),
    ) -> list[dict[str, Any]]:
        return await api_db.list_audit(state.db, campaign_id=campaign_id, limit=limit)

    # ---- events / metrics ------------------------------------------

    @api.post("/events")
    async def publish_event_endpoint(
        req: EventPublishRequest, _: Any = Depends(auth_dep)
    ) -> dict[str, Any]:
        eid = await state.events.publish(
            event_type=req.event_type,
            payload=req.payload,
            severity=req.severity,
            campaign_id=req.campaign_id,
            agent_id=req.agent_id,
            task_id=req.task_id,
            finding_id=req.finding_id,
        )
        return {"id": eid}

    @api.get("/events")
    async def list_events_endpoint(
        last_id: int = Query(0, ge=0),
        limit: int = Query(50, ge=1, le=500),
        campaign_id: str | None = Query(None),
        event_type: str | None = Query(None),
        severity: str | None = Query(None),
        _: Any = Depends(auth_dep),
    ) -> list[dict[str, Any]]:
        events = await state.events.list_since(last_id=last_id, limit=limit)
        if campaign_id is not None:
            events = [e for e in events if e.campaign_id == campaign_id]
        if event_type is not None:
            events = [e for e in events if e.event_type == event_type]
        if severity is not None:
            events = [e for e in events if e.severity == severity]
        return [e.to_sse() for e in events]

    @api.post("/metrics")
    async def publish_metric_endpoint(
        req: MetricPointRequest, _: Any = Depends(auth_dep)
    ) -> dict[str, Any]:
        if req.kind == "counter":
            await state.metrics.inc_counter(
                req.name,
                amount=req.value,
                dimensions=req.dimensions,
                is_free=req.is_free,
                is_paid=req.is_paid,
                campaign_id=req.campaign_id,
            )
        elif req.kind == "gauge":
            await state.metrics.set_gauge(
                req.name, req.value, dimensions=req.dimensions, campaign_id=req.campaign_id
            )
        else:
            await state.metrics.observe_histogram(
                req.name,
                req.value,
                bucket=req.dimensions.get("bucket", "default"),
                dimensions=req.dimensions,
                is_free=req.is_free,
                is_paid=req.is_paid,
                campaign_id=req.campaign_id,
            )
        return {"ok": True}

    @api.get("/usage")
    async def usage_endpoint(
        since: str | None = Query(None),
        until: str | None = Query(None),
        campaign_id: str | None = Query(None),
        _: Any = Depends(auth_dep),
    ) -> dict[str, Any]:
        return await state.metrics.usage_breakdown(
            since=since, until=until, campaign_id=campaign_id
        )

    @api.get("/dashboard")
    async def dashboard_endpoint(_: Any = Depends(auth_dep)) -> dict[str, Any]:
        """Aggregated counts for the dashboard view."""
        async with state.db.acquire() as conn:
            cur = await conn.execute("SELECT COUNT(*) AS n FROM campaigns")
            row = await cur.fetchone()
            total_campaigns = int(row["n"] if row else 0)
            cur = await conn.execute(
                "SELECT state, COUNT(*) AS n FROM campaigns GROUP BY state"
            )
            campaigns_by_state = {r["state"]: int(r["n"]) for r in await cur.fetchall()}
            cur = await conn.execute(
                "SELECT status, COUNT(*) AS n FROM agents GROUP BY status"
            )
            agents_by_status = {r["status"]: int(r["n"]) for r in await cur.fetchall()}
            cur = await conn.execute(
                "SELECT status, COUNT(*) AS n FROM tasks GROUP BY status"
            )
            tasks_by_status = {r["status"]: int(r["n"]) for r in await cur.fetchall()}
            cur = await conn.execute(
                "SELECT state, COUNT(*) AS n FROM findings GROUP BY state"
            )
            findings_by_state = {r["state"]: int(r["n"]) for r in await cur.fetchall()}
            cur = await conn.execute(
                "SELECT COUNT(*) AS n FROM approvals WHERE consumed_at IS NULL "
                "AND revoked_at IS NULL AND expires_at > ?",
                (_utcnow_iso(),),
            )
            row = await cur.fetchone()
            pending_approvals = int(row["n"] if row else 0)
        return {
            "campaigns": {
                "total": total_campaigns,
                "by_state": campaigns_by_state,
            },
            "agents": agents_by_status,
            "tasks": tasks_by_status,
            "findings": findings_by_state,
            "pending_approvals": pending_approvals,
        }

    # ---- SSE -------------------------------------------------------

    @api.get("/events/stream")
    async def events_stream(
        request: Request,
        last_event_id: int | None = Query(None, alias="last_event_id"),
        _: Any = Depends(auth_dep),
    ) -> StreamingResponse:
        return StreamingResponse(
            sse.stream_events(
                state.db,
                events=state.events,
                last_event_id=last_event_id or 0,
                request=request,
            ),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache, no-transform",
                "X-Accel-Buffering": "no",
            },
        )

    # ---- run bundle download (redacted zip) -------------------------

    @api.get("/campaigns/{campaign_id}/bundle")
    async def download_bundle_endpoint(
        campaign_id: str, _: Any = Depends(auth_dep)
    ) -> Response:
        from mavr.observability.bundle import export_run_bundle

        campaign = await api_db.get_campaign(state.db, campaign_id)
        if campaign is None:
            raise HTTPException(status_code=404, detail="unknown campaign")
        out_dir = Path(state.config.storage.artifact_dir).expanduser() / "bundles"
        out_dir.mkdir(parents=True, exist_ok=True)
        out_path = out_dir / f"{campaign_id}.zip"
        result = await export_run_bundle(
            state.db,
            campaign_id=campaign_id,
            output_path=out_path,
            config_snapshot=state.config,
        )
        if not out_path.exists():
            raise HTTPException(status_code=500, detail="bundle not produced")
        data = out_path.read_bytes()
        return Response(
            content=data,
            media_type="application/zip",
            headers={
                "Content-Disposition": f'attachment; filename="{out_path.name}"',
                "X-MAVR-Bundle-Size": str(result.size_bytes),
            },
        )

    fastapi_app.include_router(api)

    # ---- UI (Jinja + htmx) -----------------------------------------

    if STATIC_DIR.exists():
        fastapi_app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    templates = _make_templates()

    @fastapi_app.get("/", response_class=HTMLResponse)
    async def index(request: Request) -> HTMLResponse:
        if not client_loopback(request):
            return HTMLResponse(
                "<h1>MAVR</h1><p>UI is only available on loopback.</p>",
                status_code=403,
            )
        return templates.TemplateResponse(
            request,
            "index.html",
            {
                "token": state.token,
                "url": f"http://{state.bind_host}:{state.config.server.port}",
            },
        )

    @fastapi_app.get("/dashboard", response_class=HTMLResponse)
    async def dashboard(request: Request) -> HTMLResponse:
        return templates.TemplateResponse(request, "dashboard.html", {"token": state.token})

    @fastapi_app.get("/activity", response_class=HTMLResponse)
    async def activity(request: Request) -> HTMLResponse:
        return templates.TemplateResponse(request, "activity.html", {"token": state.token})

    @fastapi_app.get("/findings", response_class=HTMLResponse)
    async def findings(request: Request) -> HTMLResponse:
        return templates.TemplateResponse(request, "findings.html", {"token": state.token})

    @fastapi_app.get("/providers", response_class=HTMLResponse)
    async def providers(request: Request) -> HTMLResponse:
        return templates.TemplateResponse(request, "providers.html", {"token": state.token})

    @fastapi_app.get("/usage", response_class=HTMLResponse)
    async def usage(request: Request) -> HTMLResponse:
        return templates.TemplateResponse(request, "usage.html", {"token": state.token})

    @fastapi_app.get("/policy", response_class=HTMLResponse)
    async def policy(request: Request) -> HTMLResponse:
        return templates.TemplateResponse(request, "policy.html", {"token": state.token})

    @fastapi_app.get("/logs", response_class=HTMLResponse)
    async def logs(request: Request) -> HTMLResponse:
        return templates.TemplateResponse(request, "logs.html", {"token": state.token})

    @fastapi_app.get("/healthz", response_class=PlainTextResponse)
    async def healthz() -> PlainTextResponse:
        return PlainTextResponse("ok")

    return App(state=state, fastapi=fastapi_app)


def _utcnow_iso() -> str:
    from datetime import UTC, datetime

    return datetime.now(UTC).isoformat()


def client_loopback(request: Request) -> bool:
    """Return True if the connecting client is on a loopback address."""
    from mavr.api.auth import client_is_localhost

    return client_is_localhost(request.client.host if request.client else None)


__all__ = [
    "App",
    "AppState",
    "STATIC_DIR",
    "TEMPLATES_DIR",
    "UI_DIR",
    "build_app",
    "client_loopback",
]
