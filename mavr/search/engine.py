"""Web search subsystem.

Wraps the ``ddgs`` library (DuckDuckGo's metasearch engines) with:

* **deduplication** by URL + host, so the same page never appears
  twice in a single result set;
* **result limits** and **safe-search** configured from
  :class:`mavr.config.SearchConfig`;
* **caching** keyed on ``(query, top_n, safe_search)`` so repeated
  calls in the same campaign don't hammer the upstream;
* **scope filtering** that applies the campaign's scope policy to
  each result URL before it can be followed up by an extraction
  task;
* **provenance** captured as a :class:`schema.SearchResult` row
  per result, recording the query, timestamp, engine, rank, URL,
  title, snippet, ranking, and whether the URL was in-scope or
  filtered out.

The engine never decides whether to call the model or run code —
it just produces :class:`schema.SearchResult` objects and lets the
agent layer use them.
"""
from __future__ import annotations

import hashlib
import json
import re
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

from mavr.agents import identity as identity_mod
from mavr.config.loader import SearchConfig
from mavr.observability.logging import get_logger
from mavr.policy.engine import (
    ActionClass,
    RateCounter,
    ScopePolicyEngine,
    ToolCall,
    evaluate_url,
)
from mavr.schemas import entities as schema

log = get_logger(__name__)


# ---- exceptions ------------------------------------------------------------


class SearchError(RuntimeError):
    """Base class for search failures."""


class SearchBackendUnavailable(SearchError):
    """ddgs is not importable in this environment."""


class SearchConfigError(SearchError):
    """The search config is invalid (e.g. unknown backend)."""


# ---- data types -----------------------------------------------------------


@dataclass(frozen=True)
class SearchHit:
    """A single, normalized search hit before persistence."""

    url: str
    title: str
    snippet: str
    rank: int
    engine: str
    in_scope: bool = True
    source_status: str = "ok"


@dataclass
class SearchOutcome:
    """The full result of a search call."""

    query: str
    engine: str
    safe_search: str
    retrieved_at: float
    hits: list[SearchHit] = field(default_factory=list)
    cache_hit: bool = False
    error: str | None = None

    @property
    def urls(self) -> list[str]:
        return [h.url for h in self.hits]

    @property
    def in_scope_urls(self) -> list[str]:
        return [h.url for h in self.hits if h.in_scope]


# ---- helpers --------------------------------------------------------------


_SAFE_SEARCH_MAP: dict[str, str] = {
    "strict": "on",
    "moderate": "moderate",
    "off": "off",
}


def _normalize_safe_search(value: str) -> str:
    v = (value or "").strip().lower()
    if v not in _SAFE_SEARCH_MAP:
        raise SearchConfigError(
            f"safe_search must be one of {sorted(_SAFE_SEARCH_MAP)}; got {value!r}"
        )
    return _SAFE_SEARCH_MAP[v]


_URL_NORMALIZE_RE = re.compile(r"^https?://", re.IGNORECASE)


def _normalize_url(url: str) -> str:
    """Collapse trivial URL variants for dedup (lowercase host, strip
    trailing slash). Doesn't fully canonicalize — that's a much
    bigger problem — but it catches the common cases.
    """
    parsed = urlparse(url.strip())
    if not parsed.scheme or not parsed.netloc:
        return url.strip()
    host = parsed.hostname or ""
    host = host.lower()
    # Rebuild netloc with normalized host; preserve explicit port.
    port = parsed.port
    netloc = host if port is None else f"{host}:{port}"
    path = parsed.path or ""
    rebuilt = f"{parsed.scheme.lower()}://{netloc}{path}"
    if parsed.query:
        rebuilt += "?" + parsed.query
    # Strip trailing slash EXCEPT for the root path.
    if rebuilt.endswith("/") and path != "/":
        rebuilt = rebuilt.rstrip("/")
    return rebuilt


def _cache_key(query: str, top_n: int, safe_search: str) -> str:
    payload = json.dumps(
        {"q": query.strip().lower(), "n": top_n, "s": safe_search},
        sort_keys=True,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


# ---- in-memory cache ------------------------------------------------------


class _ResultCache:
    """Tiny TTL cache; survives the lifetime of one SearchEngine.

    Production code wires the cache into the artifact store if a
    longer-lived cache is needed, but in-memory covers the common
    case of "agent retries the same query a few times in a row".
    """

    def __init__(self, *, max_entries: int = 256) -> None:
        self._store: dict[str, tuple[float, SearchOutcome]] = {}
        self._max = max_entries

    def get(self, key: str) -> SearchOutcome | None:
        entry = self._store.get(key)
        if entry is None:
            return None
        ts, outcome = entry
        if ts <= time.monotonic():
            self._store.pop(key, None)
            return None
        return outcome

    def set(self, key: str, outcome: SearchOutcome, *, ttl_seconds: int = 300) -> None:
        if len(self._store) >= self._max:
            # Drop the oldest entry.
            oldest_key = min(self._store, key=lambda k: self._store[k][0])
            self._store.pop(oldest_key, None)
        self._store[key] = (time.monotonic() + ttl_seconds, outcome)

    def clear(self) -> None:
        self._store.clear()


# ---- engine ---------------------------------------------------------------


class SearchEngine:
    """Stateless-ish wrapper around ddgs.

    The engine is safe to instantiate per campaign (or per worker
    thread) — the only mutable state is the in-memory cache, which
    is bounded and self-clearing.
    """

    def __init__(
        self,
        *,
        config: SearchConfig | None = None,
        cache: _ResultCache | None = None,
    ) -> None:
        self._config = config or SearchConfig()
        self._cache = cache or _ResultCache()

    @property
    def config(self) -> SearchConfig:
        return self._config

    def _call_ddgs(
        self, query: str, top_n: int, safe_search: str
    ) -> list[dict[str, Any]]:
        try:
            from ddgs import DDGS as _DDGS
        except ImportError as exc:  # pragma: no cover
            raise SearchBackendUnavailable(
                "ddgs is not installed; install with `pip install ddgs`"
            ) from exc
        with _DDGS() as ddgs:
            return list(
                ddgs.text(
                    query,
                    region="us-en",
                    safesearch=safe_search,
                    max_results=top_n,
                )
            )

    @staticmethod
    def _to_hit(raw: dict[str, Any], *, rank: int, engine: str) -> SearchHit | None:
        url = (raw.get("href") or raw.get("url") or "").strip()
        if not url:
            return None
        title = (raw.get("title") or "").strip()
        snippet = (raw.get("body") or raw.get("snippet") or "").strip()
        return SearchHit(
            url=url,
            title=title,
            snippet=snippet,
            rank=rank,
            engine=engine,
            in_scope=True,            # filtered later
            source_status="ok",
        )

    def _filter_scope(
        self,
        hits: list[SearchHit],
        *,
        campaign: schema.Campaign,
        scope: schema.ScopePolicy,
    ) -> list[SearchHit]:
        engine = ScopePolicyEngine(resolve_dns=False)
        rate = RateCounter(per_minute=0)        # rate handled elsewhere
        out: list[SearchHit] = []
        for hit in hits:
            try:
                ips = ScopePolicyEngine.resolve_now(
                    (urlparse(hit.url).hostname or "").lower()
                )
            except Exception:  # noqa: BLE001
                ips = ()
            call = ToolCall(
                url=hit.url,
                method="GET",
                action_class=ActionClass.READ.value,
                payload_summary="search result follow-up",
                resolved_ips=ips,
            )
            decision = engine.evaluate(campaign, scope, call, rate=rate)
            if decision.kind.value == "allow":
                out.append(
                    SearchHit(
                        url=hit.url,
                        title=hit.title,
                        snippet=hit.snippet,
                        rank=hit.rank,
                        engine=hit.engine,
                        in_scope=True,
                        source_status="ok",
                    )
                )
            else:
                out.append(
                    SearchHit(
                        url=hit.url,
                        title=hit.title,
                        snippet=hit.snippet,
                        rank=hit.rank,
                        engine=hit.engine,
                        in_scope=False,
                        source_status=f"filtered:{decision.rule}",
                    )
                )
        return out

    @staticmethod
    def _dedup(hits: list[SearchHit]) -> list[SearchHit]:
        """Drop exact URL duplicates. Keep the first occurrence (best
        rank). Track the first rank each unique URL was seen at.
        """
        seen: dict[str, SearchHit] = {}
        for hit in hits:
            key = _normalize_url(hit.url)
            if key in seen:
                continue
            seen[key] = hit
        return list(seen.values())

    def search(
        self,
        query: str,
        *,
        campaign: schema.Campaign,
        scope: schema.ScopePolicy,
        top_n: int | None = None,
        safe_search: str | None = None,
        use_cache: bool = True,
    ) -> SearchOutcome:
        """Run a search, return deduplicated, scope-filtered results.

        Args:
            query: The user's query string.
            campaign: The active campaign (for scope filter + provenance).
            scope: The campaign's scope policy.
            top_n: Override the configured result limit.
            safe_search: Override the configured safe-search setting.
            use_cache: When False, bypass the in-memory cache.

        Returns:
            A :class:`SearchOutcome` whose ``hits`` field contains
            :class:`SearchHit` objects. The caller is expected to
            persist these as :class:`schema.SearchResult` rows.
        """
        if not isinstance(query, str) or not query.strip():
            raise SearchConfigError("query must be a non-empty string")

        top = top_n if top_n is not None else self._config.top_n
        ss = _normalize_safe_search(
            safe_search if safe_search is not None else self._config.safe_search
        )
        outcome = SearchOutcome(
            query=query,
            engine="ddgs",
            safe_search=ss,
            retrieved_at=time.time(),
        )

        cache_key = _cache_key(query, top, ss) if use_cache else None
        if cache_key is not None:
            cached = self._cache.get(cache_key)
            if cached is not None:
                outcome = SearchOutcome(
                    query=query,
                    engine=cached.engine,
                    safe_search=cached.safe_search,
                    retrieved_at=cached.retrieved_at,
                    hits=list(cached.hits),
                    cache_hit=True,
                )
                return outcome

        try:
            raw = self._call_ddgs(query, top, ss)
        except SearchBackendUnavailable:
            outcome.error = "ddgs not available"
            return outcome
        except Exception as exc:  # noqa: BLE001
            log.warning("ddgs_error", query=query, error=str(exc))
            outcome.error = f"backend error: {exc}"
            return outcome

        engine_name = "ddgs"
        candidates: list[SearchHit] = []
        for i, item in enumerate(raw, start=1):
            hit = self._to_hit(item, rank=i, engine=engine_name)
            if hit is not None:
                candidates.append(hit)
        deduped = self._dedup(candidates)
        filtered = self._filter_scope(deduped, campaign=campaign, scope=scope)
        # Cap to the requested top_n. The backend may have returned
        # more (some engines don't strictly honor max_results).
        if len(filtered) > top:
            filtered = filtered[:top]
        outcome.hits = filtered

        if cache_key is not None:
            self._cache.set(cache_key, outcome, ttl_seconds=300)
        return outcome


# ---- persistence helpers --------------------------------------------------


async def persist_results(
    outcome: SearchOutcome,
    *,
    campaign_id: str,
    task_id: str | None = None,
    conn: Any,
) -> list[schema.SearchResult]:
    """Write each :class:`SearchHit` to the ``search_results`` table.

    The ``conn`` parameter must be an open :class:`aiosqlite.Connection`.
    The function does NOT commit — the caller is expected to manage
    the transaction so the writes are atomic with the rest of the
    task.

    (We accept a connection, not a :class:`Database`, because
    :class:`Database.execute` re-acquires the connection lock and
    would deadlock when the caller already holds it.)
    """
    rows: list[schema.SearchResult] = []
    from datetime import UTC, datetime

    now = schema._ensure_utc(datetime.now(UTC))
    for hit in outcome.hits:
        row = schema.SearchResult(
            id=identity_mod.mint_uuid(),
            task_id=task_id,
            campaign_id=campaign_id,
            query=outcome.query,
            engine=outcome.engine,
            rank=hit.rank,
            url=hit.url,
            title=hit.title,
            snippet=hit.snippet,
            source_status=hit.source_status,
            in_scope=hit.in_scope,
            retrieved_at=now,
        )
        await conn.execute(
            "INSERT INTO search_results("
            "id, schema_version, task_id, campaign_id, query, engine, rank, "
            "url, title, snippet, source_status, in_scope, retrieved_at"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                row.id,
                row.schema_version,
                row.task_id,
                row.campaign_id,
                row.query,
                row.engine,
                row.rank,
                row.url,
                row.title,
                row.snippet,
                row.source_status,
                1 if row.in_scope else 0,
                row.retrieved_at.isoformat(),
            ),
        )
        rows.append(row)
    return rows


# ---- public helpers re-exported for clarity ------------------------------


__all__ = [
    "SearchEngine",
    "SearchHit",
    "SearchOutcome",
    "SearchError",
    "SearchBackendUnavailable",
    "SearchConfigError",
    "evaluate_url",
]
