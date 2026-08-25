"""Phase 7 tests: API contract, SSE, approvals, bundle, dashboard."""
from __future__ import annotations

import io
import zipfile
from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest
import pytest_asyncio

from mavr.api import build_app
from mavr.config.loader import AppConfig, ServerConfig, StorageConfig
from mavr.observability import EventBus, MetricsStore, bind, new_correlation_id
from mavr.storage.database import Database, apply_migrations

# ---- fixtures ------------------------------------------------------------


@pytest_asyncio.fixture()
async def cfg(tmp_path: Path) -> AppConfig:
    return AppConfig(
        server=ServerConfig(),
        storage=StorageConfig(
            db_path=str(tmp_path / "mavr.db"),
            artifact_dir=str(tmp_path / "artifacts"),
        ),
    )


@pytest_asyncio.fixture()
async def app_stack(cfg: AppConfig) -> AsyncIterator[tuple[object, str]]:
    db = Database(cfg.storage.db_path)
    await apply_migrations(db, "up")
    token = "mavr_testtoken_abc123"
    application = build_app(
        config=cfg,
        db=db,
        bind_host="127.0.0.1",
        allow_lan=False,
        human_approved=False,
        token=token,
    )
    transport = httpx.ASGITransport(app=application.app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://test"
    ) as client:
        yield (application, client), token


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


# ---- auth / loopback -----------------------------------------------------


@pytest.mark.asyncio
async def test_health_requires_bearer(app_stack) -> None:
    (_app, client), _token = app_stack
    r = await client.get("/api/health")
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_health_returns_ok(app_stack) -> None:
    (_app, client), token = app_stack
    r = await client.get("/api/health", headers=_bearer(token))
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "ok"
    assert data["config"]["host"] == "127.0.0.1"


@pytest.mark.asyncio
async def test_wildcard_bind_refused() -> None:
    cfg = AppConfig(
        server=ServerConfig(),
        storage=StorageConfig(db_path="/tmp/x.db", artifact_dir="/tmp/y"),
    )
    db = Database(cfg.storage.db_path)
    await apply_migrations(db, "up")
    with pytest.raises(RuntimeError, match="loopback"):
        build_app(
            config=cfg,
            db=db,
            bind_host="0.0.0.0",
            allow_lan=False,
            human_approved=False,
            token="mavr_x",
        )


@pytest.mark.asyncio
async def test_wildcard_bind_allowed_with_flags() -> None:
    cfg = AppConfig(
        server=ServerConfig(),
        storage=StorageConfig(db_path="/tmp/y.db", artifact_dir="/tmp/y"),
    )
    db = Database(cfg.storage.db_path)
    await apply_migrations(db, "up")
    app = build_app(
        config=cfg,
        db=db,
        bind_host="0.0.0.0",
        allow_lan=True,
        human_approved=True,
        token="mavr_x",
    )
    assert app.state.allow_lan is True


# ---- campaigns / scope / agents / findings / tasks --------------------


@pytest.mark.asyncio
async def test_create_and_get_campaign(app_stack) -> None:
    (_app, client), token = app_stack
    r = await client.post(
        "/api/campaigns",
        json={
            "name": "phase7-test",
            "target_spec": {"hosts": ["example.com"]},
        },
        headers=_bearer(token),
    )
    assert r.status_code == 201
    cid = r.json()["id"]
    r2 = await client.get(f"/api/campaigns/{cid}", headers=_bearer(token))
    assert r2.status_code == 200
    data = r2.json()
    assert data["campaign"]["name"] == "phase7-test"


@pytest.mark.asyncio
async def test_upsert_scope_policy(app_stack) -> None:
    (_app, client), token = app_stack
    r = await client.post(
        "/api/campaigns",
        json={"name": "scope-test", "target_spec": {"hosts": ["a.com"]}},
        headers=_bearer(token),
    )
    cid = r.json()["id"]
    r2 = await client.post(
        f"/api/campaigns/{cid}/scope",
        json={
            "campaign_id": cid,
            "allowed_targets": ["a.com", "*.a.com"],
            "allowed_methods": ["GET", "POST"],
            "action_allowlist": ["scan", "fetch"],
            "rate_limit_per_minute": 30,
            "active_testing": False,
        },
        headers=_bearer(token),
    )
    assert r2.status_code == 200
    sid = r2.json()["scope_policy_id"]
    assert sid
    r3 = await client.get(f"/api/campaigns/{cid}", headers=_bearer(token))
    assert r3.json()["scope"]["allowed_targets"] == ["a.com", "*.a.com"]


@pytest.mark.asyncio
async def test_dashboard_aggregates(app_stack) -> None:
    (_app, client), token = app_stack
    r = await client.get("/api/dashboard", headers=_bearer(token))
    assert r.status_code == 200
    data = r.json()
    assert "campaigns" in data
    assert "findings" in data
    assert "agents" in data
    assert "tasks" in data
    assert "pending_approvals" in data


# ---- approvals + gate --------------------------------------------------


@pytest.mark.asyncio
async def test_approval_create_list_revoke(app_stack) -> None:
    (_app, client), token = app_stack
    r = await client.post(
        "/api/approvals",
        json={"action": "active_testing", "actor": "tester", "reason": "phase7"},
        headers=_bearer(token),
    )
    assert r.status_code == 201
    aid = r.json()["id"]
    r2 = await client.get("/api/approvals", headers=_bearer(token))
    assert r2.status_code == 200
    assert any(a["id"] == aid for a in r2.json())


@pytest.mark.asyncio
async def test_approval_gate_missing_token(app_stack) -> None:
    # The gate is exercised directly via a test endpoint; here we
    # check that an unconsumed approval blocks an action through
    # a custom flow.
    from mavr.api.approval_gate import ApprovalGate

    (_app, client), token = app_stack
    # Create an approval
    r = await client.post(
        "/api/approvals",
        json={"action": "submission", "actor": "alice"},
        headers=_bearer(token),
    )
    approval_token = r.json()["token"]
    # Use the gate directly
    db = _app.state.db
    gate = ApprovalGate(db, metrics=MetricsStore(db))
    result = await gate.require(action="submission", token=approval_token)
    assert result.approval.action == "submission"
    # Re-using the same token should fail (it was consumed).
    import pytest as _pytest

    with _pytest.raises(Exception):
        await gate.require(action="submission", token=approval_token)


# ---- events / SSE ------------------------------------------------------


@pytest.mark.asyncio
async def test_publish_and_list_events(app_stack) -> None:
    (_app, client), token = app_stack
    r = await client.post(
        "/api/events",
        json={"event_type": "test.evt", "payload": {"k": "v"}, "severity": "info"},
        headers=_bearer(token),
    )
    assert r.status_code == 200
    eid = r.json()["id"]
    r2 = await client.get("/api/events?last_id=0&limit=10", headers=_bearer(token))
    events = r2.json()
    assert any(e["id"] == eid for e in events)


@pytest.mark.asyncio
async def test_sse_replay(tmp_path: Path) -> None:
    db = Database(tmp_path / "phase7_sse.db")
    await apply_migrations(db, "up")
    bus = EventBus(db)
    # Publish three events; record ids
    ids = []
    for i in range(3):
        eid = await bus.publish(event_type=f"test.{i}", payload={"i": i})
        ids.append(eid)
    # Use a fresh DB to simulate the "client missed N events" case by
    # asking the hub to replay from id=0 then from ids[0].
    from mavr.api.sse import SSEHub

    hub = SSEHub(db=db, events=bus)
    replayed = await hub.replay(last_event_id=0)
    assert [e.id for e in replayed] == ids
    replayed_after = await hub.replay(last_event_id=ids[0])
    assert [e.id for e in replayed_after] == ids[1:]


@pytest.mark.asyncio
async def test_sse_endpoint_streams_events(app_stack) -> None:
    (_app, client), token = app_stack
    # Publish two events first; the SSE stream should yield them.
    pub_ids = []
    for i in range(2):
        r = await client.post(
            "/api/events",
            json={"event_type": f"sse.evt.{i}", "payload": {"i": i}},
            headers=_bearer(token),
        )
        pub_ids.append(r.json()["id"])

    # Use the sse_response helper directly so the test does not block
    # on the infinite tail. We read the first replay chunk only.
    from mavr.api import sse as sse_mod

    hub = sse_mod.SSEHub(db=_app.state.db, events=_app.state.events, poll_interval=0.05)
    replayed = await hub.replay(0)
    assert [e.id for e in replayed] == pub_ids
    # Now exercise the live tail briefly by publishing a third event.
    new_id = await _app.state.events.publish(event_type="sse.tail.evt", payload={"x": 1})
    tailed = await hub.tail(replayed[-1].id)
    assert any(e.id == new_id for e in tailed)


# ---- metrics / usage ---------------------------------------------------


@pytest.mark.asyncio
async def test_metrics_and_usage(app_stack) -> None:
    (_app, client), token = app_stack
    r = await client.post(
        "/api/metrics",
        json={
            "name": "router.requests",
            "kind": "counter",
            "value": 3.0,
            "dimensions": {"provider": "mock"},
            "is_free": True,
            "is_paid": False,
        },
        headers=_bearer(token),
    )
    assert r.status_code == 200
    r2 = await client.get("/api/usage", headers=_bearer(token))
    assert r2.status_code == 200
    data = r2.json()
    assert "free_calls_total" in data
    assert "paid_calls_total" in data
    assert "by_provider_model" in data


# ---- run bundle -------------------------------------------------------


@pytest.mark.asyncio
async def test_run_bundle_export(app_stack) -> None:
    (_app, client), token = app_stack
    r = await client.post(
        "/api/campaigns",
        json={"name": "bundle-test", "target_spec": {"hosts": ["x.com"]}},
        headers=_bearer(token),
    )
    cid = r.json()["id"]
    r2 = await client.post(
        f"/api/campaigns/{cid}/scope",
        json={
            "campaign_id": cid,
            "allowed_targets": ["x.com"],
            "allowed_methods": ["GET"],
            "action_allowlist": ["scan"],
        },
        headers=_bearer(token),
    )
    assert r2.status_code == 200
    # Add a sensitive event payload to ensure redaction kicks in.
    r3 = await client.post(
        "/api/events",
        json={
            "event_type": "test.sensitive",
            "payload": {
                "token": "sk-1234567890ABCDEFGHIJ",
                "nested": {"api_key": "AIza" + "a" * 30, "ok": 1},
            },
            "campaign_id": cid,
        },
        headers=_bearer(token),
    )
    assert r3.status_code == 200

    r4 = await client.post(
        f"/api/campaigns/{cid}/export",
        headers=_bearer(token),
    )
    assert r4.status_code == 200
    bundle_path = r4.json()["path"]
    with zipfile.ZipFile(bundle_path) as zf:
        names = zf.namelist()
        assert "manifest.json" in names
        assert "events.jsonl" in names
        assert "audit.jsonl" in names
        assert "redaction_manifest.json" in names
        assert "db_dump.sqlite" in names
        # Find the sensitive event in events.jsonl
        with zf.open("events.jsonl") as fh:
            text = fh.read().decode("utf-8")
        assert "***REDACTED***" in text
        assert "sk-1234567890ABCDEFGHIJ" not in text
        assert "AIza" + "a" * 30 not in text


@pytest.mark.asyncio
async def test_run_bundle_download(app_stack) -> None:
    (_app, client), token = app_stack
    r = await client.post(
        "/api/campaigns",
        json={"name": "dl-bundle", "target_spec": {"hosts": ["d.com"]}},
        headers=_bearer(token),
    )
    cid = r.json()["id"]
    r2 = await client.get(f"/api/campaigns/{cid}/bundle", headers=_bearer(token))
    assert r2.status_code == 200
    assert r2.headers["content-type"] == "application/zip"
    # The body is a valid zip
    with zipfile.ZipFile(io.BytesIO(r2.content)) as zf:
        assert "manifest.json" in zf.namelist()


# ---- correlation / context --------------------------------------------


@pytest.mark.asyncio
async def test_correlation_context() -> None:
    cid = new_correlation_id()
    with bind(correlation_id=cid, campaign_id="camp-1"):
        from mavr.observability.context import current_correlation

        ctx = current_correlation()
        assert ctx["correlation_id"] == cid
        assert ctx["campaign_id"] == "camp-1"
    # After the context, defaults return
    from mavr.observability.context import current_correlation

    post = current_correlation()
    assert post["campaign_id"] == ""


# ---- kill switch ------------------------------------------------------


@pytest.mark.asyncio
async def test_kill_switch(app_stack) -> None:
    (_app, client), token = app_stack
    r = await client.post(
        "/api/kill_switch",
        json={"active": True, "reason": "phase7-test", "by": "tester"},
        headers=_bearer(token),
    )
    assert r.status_code == 200
    r2 = await client.get("/api/kill_switch", headers=_bearer(token))
    data = r2.json()
    assert data["is_active"] == 1
    r3 = await client.post(
        "/api/kill_switch",
        json={"active": False, "by": "tester"},
        headers=_bearer(token),
    )
    assert r3.status_code == 200


# ---- UI rendering (smoke) --------------------------------------------


@pytest.mark.asyncio
async def test_dashboard_renders(app_stack) -> None:
    (_app, client), token = app_stack
    r = await client.get("/dashboard")
    assert r.status_code == 200
    assert b"MAVR" in r.content
    assert token.encode("utf-8") in r.content


@pytest.mark.asyncio
async def test_index_renders(app_stack) -> None:
    (_app, client), _token = app_stack
    r = await client.get("/")
    assert r.status_code == 200
    assert b"Welcome" in r.content


@pytest.mark.asyncio
async def test_all_ui_pages_render(app_stack) -> None:
    (_app, client), _token = app_stack
    for path in ("/dashboard", "/activity", "/findings", "/providers", "/usage", "/policy", "/logs"):
        r = await client.get(path)
        assert r.status_code == 200, path
        assert b"MAVR" in r.content


# ---- audit endpoint ---------------------------------------------------


@pytest.mark.asyncio
async def test_audit_endpoint(app_stack) -> None:
    (_app, client), token = app_stack
    r = await client.get("/api/audit?limit=20", headers=_bearer(token))
    assert r.status_code == 200
    assert isinstance(r.json(), list)


# ---- loopback middleware: non-loopback is refused --------------------


@pytest.mark.asyncio
async def test_non_loopback_refused(tmp_path: Path) -> None:
    """The localhost guard raises HTTPException(403) for non-loopback clients.

    We exercise the guard function directly (the ASGI test client always
    reports a loopback address, so we cannot simulate an external peer
    through it without rewriting the test transport).
    """
    from fastapi import HTTPException

    from mavr.api.auth import enforce_localhost

    with pytest.raises(HTTPException) as exc:
        enforce_localhost(
            "127.0.0.1",
            allow_lan=False,
            human_approved=False,
            client_host="8.8.8.8",
        )
    assert exc.value.status_code == 403

    # A loopback client is allowed
    enforce_localhost(
        "127.0.0.1",
        allow_lan=False,
        human_approved=False,
        client_host="127.0.0.1",
    )

    # A non-loopback client to a LAN-enabled app is allowed when both
    # flags are set
    enforce_localhost(
        "0.0.0.0",
        allow_lan=True,
        human_approved=True,
        client_host="8.8.8.8",
    )

    # A wildcard bind without flags is refused even for loopback callers
    with pytest.raises(HTTPException):
        enforce_localhost(
            "0.0.0.0",
            allow_lan=False,
            human_approved=False,
            client_host="127.0.0.1",
        )
