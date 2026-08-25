"""Tests for mavr.search.engine.

Covers the ddgs wrapper: dedup, result limit, safe-search config,
cache, scope filtering, and provenance persistence.
"""
from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import pytest

from mavr.config.loader import SearchConfig
from mavr.schemas import entities as schema
from mavr.search import engine


def _make_campaign(scope: schema.ScopePolicy) -> schema.Campaign:
    now = datetime.now(UTC)
    return schema.Campaign(
        id=scope.campaign_id,
        schema_version=schema.SCHEMA_VERSION,
        name="t",
        target_spec={},
        created_at=now,
        updated_at=now,
    )


def _make_scope(
    *,
    allowed_targets: list[str] | None = None,
    human_approved: bool = False,
) -> schema.ScopePolicy:
    now = datetime.now(UTC)
    return schema.ScopePolicy(
        id=str(uuid4()),
        campaign_id=str(uuid4()),
        allowed_targets=allowed_targets or [],
        allowed_methods=["GET", "HEAD"],
        action_allowlist=["read"],
        rate_limit_per_minute=60,
        active_testing=False,
        explicit_unsafe_networking=False,
        human_approved=human_approved,
        created_at=now,
        updated_at=now,
    )


# ---- dedup ----------------------------------------------------------------


def test_dedup_drops_exact_dupes() -> None:
    hits = [
        engine.SearchHit(url="https://a.com/x", title="a", snippet="s", rank=1, engine="x"),
        engine.SearchHit(url="https://a.com/x", title="a2", snippet="s2", rank=2, engine="x"),
        engine.SearchHit(url="https://b.com/y", title="b", snippet="s", rank=3, engine="x"),
    ]
    out = engine.SearchEngine._dedup(hits)
    assert len(out) == 2
    urls = sorted(h.url for h in out)
    assert urls == ["https://a.com/x", "https://b.com/y"]


def test_dedup_normalizes_trailing_slash() -> None:
    hits = [
        engine.SearchHit(url="https://a.com/x/", title="", snippet="", rank=1, engine="x"),
        engine.SearchHit(url="https://a.com/x", title="", snippet="", rank=2, engine="x"),
    ]
    out = engine.SearchEngine._dedup(hits)
    assert len(out) == 1


def test_dedup_normalizes_case() -> None:
    hits = [
        engine.SearchHit(url="https://A.com/x", title="", snippet="", rank=1, engine="x"),
        engine.SearchHit(url="https://a.com/x", title="", snippet="", rank=2, engine="x"),
    ]
    out = engine.SearchEngine._dedup(hits)
    assert len(out) == 1


# ---- cache key ------------------------------------------------------------


def test_cache_key_stable() -> None:
    a = engine._cache_key("foo", 5, "moderate")
    b = engine._cache_key("foo", 5, "moderate")
    assert a == b
    c = engine._cache_key("FOO", 5, "moderate")
    assert c == b        # normalized lowercase
    d = engine._cache_key("foo", 6, "moderate")
    assert d != a


# ---- safe-search normalization -------------------------------------------


def test_safe_search_known_values() -> None:
    assert engine._normalize_safe_search("strict") == "on"
    assert engine._normalize_safe_search("moderate") == "moderate"
    assert engine._normalize_safe_search("off") == "off"


def test_safe_search_unknown_raises() -> None:
    with pytest.raises(engine.SearchConfigError):
        engine._normalize_safe_search("nuclear")


# ---- engine.search() ------------------------------------------------------


class _StubDDGS:
    """Mimics the ddgs context-manager interface for tests."""

    def __init__(self, rows: list[dict[str, Any]]) -> None:
        self._rows = rows

    def __enter__(self) -> _StubDDGS:
        return self

    def __exit__(self, *args: Any) -> None:
        return None

    def text(self, query: str, **kwargs: Any) -> list[dict[str, Any]]:
        return list(self._rows)


def test_search_returns_deduped_filtered_results(monkeypatch: pytest.MonkeyPatch) -> None:
    rows = [
        {"href": "https://allowed.example.com/a", "title": "A", "body": "snippet"},
        {"href": "https://allowed.example.com/a", "title": "dup", "body": "dup"},
        {"href": "https://blocked.example.com/b", "title": "B", "body": "bad"},
    ]
    import ddgs as ddgs_mod

    import mavr.search.engine as engine_mod

    monkeypatch.setattr(ddgs_mod, "DDGS", lambda: _StubDDGS(rows))

    # Pretend the policy engine resolves the two allowed IPs to public
    # ones. We patch ScopePolicyEngine.evaluate to a simple whitelist.
    scope = _make_scope(allowed_targets=["allowed.example.com"])
    campaign = _make_campaign(scope)

    # Patch resolve_now so DNS doesn't actually happen.
    monkeypatch.setattr(
        engine_mod.ScopePolicyEngine, "resolve_now",
        staticmethod(lambda host: ("1.2.3.4",) if "allowed" in host else ("5.6.7.8",)),
    )

    eng = engine.SearchEngine(config=SearchConfig(top_n=10))
    out = eng.search("hello", campaign=campaign, scope=scope, use_cache=False)
    assert out.error is None
    urls = [h.url for h in out.hits]
    assert "https://allowed.example.com/a" in urls
    assert "https://blocked.example.com/b" in urls
    # In-scope marker set correctly.
    in_scope_urls = [h.url for h in out.hits if h.in_scope]
    assert in_scope_urls == ["https://allowed.example.com/a"]
    # Dedup applied.
    assert sum(1 for h in out.hits if h.url == "https://allowed.example.com/a") == 1


def test_search_respects_top_n(monkeypatch: pytest.MonkeyPatch) -> None:
    rows = [
        {"href": f"https://allowed.example.com/p{i}", "title": "", "body": ""}
        for i in range(5)
    ]
    import ddgs as ddgs_mod

    import mavr.search.engine as engine_mod

    monkeypatch.setattr(ddgs_mod, "DDGS", lambda: _StubDDGS(rows))
    monkeypatch.setattr(
        engine_mod.ScopePolicyEngine, "resolve_now",
        staticmethod(lambda host: ("1.2.3.4",)),
    )
    scope = _make_scope(allowed_targets=["allowed.example.com"])
    campaign = _make_campaign(scope)
    eng = engine.SearchEngine(config=SearchConfig(top_n=3))
    out = eng.search("x", campaign=campaign, scope=scope, use_cache=False)
    assert len(out.hits) == 3


def test_search_caches_results(monkeypatch: pytest.MonkeyPatch) -> None:
    rows = [
        {"href": "https://allowed.example.com/p1", "title": "A", "body": "S"},
    ]
    import ddgs as ddgs_mod

    import mavr.search.engine as engine_mod

    call_count = {"n": 0}

    def factory() -> Any:
        class C:
            def __enter__(self_inner) -> Any: return self_inner
            def __exit__(self_inner, *a: Any) -> None: return None
            def text(self_inner, *a: Any, **kw: Any) -> Any:
                call_count["n"] += 1
                return rows
        return C()

    monkeypatch.setattr(ddgs_mod, "DDGS", factory)
    monkeypatch.setattr(
        engine_mod.ScopePolicyEngine, "resolve_now",
        staticmethod(lambda host: ("1.2.3.4",)),
    )
    scope = _make_scope(allowed_targets=["allowed.example.com"])
    campaign = _make_campaign(scope)
    eng = engine.SearchEngine(config=SearchConfig(top_n=5))
    eng.search("same", campaign=campaign, scope=scope, use_cache=True)
    out2 = eng.search("same", campaign=campaign, scope=scope, use_cache=True)
    assert call_count["n"] == 1, "second call should hit cache"
    assert out2.cache_hit is True


def test_search_provenance_persists_results(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    from mavr.storage.database import Database, apply_migrations

    db = Database(str(tmp_path / "phase5.db"))
    import asyncio

    asyncio.run(apply_migrations(db, "up"))
    campaign_id = str(uuid4())
    asyncio.run(db.execute(
        "INSERT INTO campaigns(id, schema_version, name, target_spec, state, "
        "created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            campaign_id,
            schema.SCHEMA_VERSION,
            "phase5",
            "{}",
            "active",
            datetime.now(UTC).isoformat(),
            datetime.now(UTC).isoformat(),
        ),
    ))

    rows = [
        {"href": "https://allowed.example.com/a", "title": "A", "body": "S"},
    ]
    import ddgs as ddgs_mod

    import mavr.search.engine as engine_mod

    monkeypatch.setattr(ddgs_mod, "DDGS", lambda: _StubDDGS(rows))
    monkeypatch.setattr(
        engine_mod.ScopePolicyEngine, "resolve_now",
        staticmethod(lambda host: ("1.2.3.4",)),
    )
    scope = _make_scope(allowed_targets=["allowed.example.com"])
    scope = scope.model_copy(update={"campaign_id": campaign_id})
    campaign = _make_campaign(scope)
    eng = engine.SearchEngine(config=SearchConfig(top_n=5))
    out = eng.search("q", campaign=campaign, scope=scope, use_cache=False)

    async def go() -> list[schema.SearchResult]:
        async with db.acquire() as conn:
            saved = await engine_mod.persist_results(
                out, campaign_id=campaign_id, conn=conn
            )
            await conn.commit()
            return saved

    saved = asyncio.run(go())
    assert len(saved) == 1
    assert saved[0].url == "https://allowed.example.com/a"
    assert saved[0].in_scope is True

    async def check() -> int:
        async with db.acquire() as conn:
            cur = await conn.execute(
                "SELECT COUNT(*) AS c FROM search_results WHERE campaign_id = ?",
                (campaign_id,),
            )
            row = await cur.fetchone()
            return int(row["c"])

    assert asyncio.run(check()) == 1


def test_search_empty_query_rejected() -> None:
    scope = _make_scope()
    campaign = _make_campaign(scope)
    eng = engine.SearchEngine()
    with pytest.raises(engine.SearchConfigError):
        eng.search("   ", campaign=campaign, scope=scope, use_cache=False)
