"""Fetched-page cache: content-addressed, TTL'd, single-flight (PLAN §9 — issue #298).

Multiple agents fetch the same pages; without a shared cache we waste quota
and time. This module adds the *fetch* side of §9 caching (search-query
caching lives in ``search/cache.py``):

- **Content-addressed**: page bytes go into an
  :class:`storage.artifacts.ArtifactStore` keyed by sha256; the index is
  keyed by normalized URL + fetch params, so re-fetches of identical bytes
  dedupe at the storage layer too.
- **TTL per content type**: callers pass ``content_type`` (e.g.
  ``text/html``, ``application/json``); TTLs are configurable per type with
  a default fallback.
- **Scope-change invalidation**: entries record the campaign scope
  fingerprint (same approach as ``search.cache.scope_fingerprint``);
  invalidating a scope drops exactly its entries.
- **Honest provenance on hits** (§9): a cache hit returns the original
  fetched-at timestamp and source so evidence built from cached pages stays
  truthful about when the bytes were seen.
- **Single-flight**: N concurrent ``get_or_fetch()`` calls for one URL run
  the fetch function once; the rest wait and share the result.

Metrics: hits, misses, hit rate, bandwidth saved (bytes served from cache
instead of network), in-flight dedupes.
"""

from __future__ import annotations

import hashlib
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from search.cache import scope_fingerprint
from storage.artifacts import ArtifactStore

__all__ = ["FetchCache", "CachedPage", "FetchResult"]


DEFAULT_TTL_SECONDS = 3600.0


# Normalization that maps URL variants serving identical content onto one key:
# fragment dropped (never sent to servers); trailing slash and query order
# preserved otherwise (they can change content).
def normalize_url(url: str) -> str:
    url = url.strip()
    if "#" in url:
        url = url.split("#", 1)[0]
    return url.casefold()


def index_key(url: str, fetch_params: dict[str, Any] | None) -> str:
    """Stable cache index key: normalized URL + canonicalized fetch params."""
    payload = {"url": normalize_url(url), "params": fetch_params or {}}
    blob = repr(sorted(payload["params"].items())).encode()
    param_hash = hashlib.sha256(blob).hexdigest()[:16]
    return f"{normalize_url(url)}|{param_hash}"


@dataclass(frozen=True)
class CachedPage:
    """What a caller receives on either a hit or a fresh fetch."""

    url: str
    digest: str  # sha256 of page bytes in the artifact store
    content_type: str
    size: int
    fetched_at: float  # epoch of ORIGINAL fetch (preserved across hits)
    source: str  # original fetcher/source label, preserved across hits
    from_cache: bool


@dataclass(frozen=True)
class FetchResult:
    """Internal wrapper so single-flight waiters can share outcome + stats."""

    page: CachedPage
    network_calls: int  # 1 for the leader, 0 for waiters


class FetchCache:
    """Shared, thread-safe fetched-page cache over an ArtifactStore."""

    def __init__(
        self,
        artifacts: ArtifactStore,
        default_ttl_seconds: float = DEFAULT_TTL_SECONDS,
        ttl_by_content_type: dict[str, float] | None = None,
        max_index_entries: int = 2048,
    ) -> None:
        self._artifacts = artifacts
        self._default_ttl = default_ttl_seconds
        self._ttl_by_type = dict(ttl_by_content_type or {})
        self._max_entries = max_index_entries
        self._lock = threading.RLock()
        # index key -> metadata dict
        self._index: dict[str, dict[str, Any]] = {}
        # single-flight: index key -> in-flight lock/flag
        self._inflight: dict[str, threading.Event] = {}
        self._singleflight_saved = 0
        self._hits = 0
        self._misses = 0
        self._bytes_served_from_cache = 0

    # -- TTL -----------------------------------------------------------------

    def _ttl_for(self, content_type: str) -> float:
        return self._ttl_by_type.get(content_type, self._default_ttl)

    # -- metrics ---------------------------------------------------------------

    def stats(self) -> dict[str, Any]:
        total = self._hits + self._misses
        return {
            "hits": self._hits,
            "misses": self._misses,
            "hit_rate": (self._hits / total) if total else 0.0,
            "bandwidth_saved_bytes": self._bytes_served_from_cache,
            "singleflight_deduped": self._singleflight_saved,
            "entries": len(self._index),
        }

    # -- core operations ---------------------------------------------------------

    def _lookup_live(self, key: str, now: float) -> dict[str, Any] | None:
        meta = self._index.get(key)
        if meta is None:
            return None
        if (now - meta["fetched_at"]) > self._ttl_for(meta["content_type"]):
            del self._index[key]
            return None
        return meta

    def get(
        self,
        url: str,
        fetch_params: dict[str, Any] | None = None,
        now: float | None = None,
    ) -> CachedPage | None:
        """Return the cached page if present and unexpired, else None."""
        now = time.time() if now is None else now
        key = index_key(url, fetch_params)
        with self._lock:
            meta = self._lookup_live(key, now)
            if meta is None:
                self._misses += 1
                return None
            self._hits += 1
            self._bytes_served_from_cache += meta["size"]
            return CachedPage(
                url=url,
                digest=meta["digest"],
                content_type=meta["content_type"],
                size=meta["size"],
                fetched_at=meta["fetched_at"],
                source=meta["source"],
                from_cache=True,
            )

    def put(
        self,
        url: str,
        body: bytes,
        content_type: str = "text/html",
        source: str = "",
        fetch_params: dict[str, Any] | None = None,
        scope: dict[str, Any] | list[str] | None = None,
        now: float | None = None,
    ) -> CachedPage:
        """Store a freshly fetched page."""
        now = time.time() if now is None else now
        art = self._artifacts.put_bytes(body)
        key = index_key(url, fetch_params)
        meta = {
            "digest": art.digest,
            "content_type": content_type,
            "size": len(body),
            "fetched_at": now,
            "source": source,
            "scope_fp": scope_fingerprint(scope),
        }
        with self._lock:
            self._index[key] = meta
            self._evict_locked()
        return CachedPage(
            url=url,
            digest=art.digest,
            content_type=content_type,
            size=len(body),
            fetched_at=now,
            source=source,
            from_cache=False,
        )

    def get_or_fetch(
        self,
        url: str,
        fetch_fn: Callable[[str], tuple[bytes, str]],
        fetch_params: dict[str, Any] | None = None,
        source: str = "",
        scope: dict[str, Any] | list[str] | None = None,
        now: float | None = None,
    ) -> CachedPage:
        """Return cached page or fetch once, even under concurrency.

        ``fetch_fn(url) -> (body, content_type)`` performs the actual network
        call. Concurrent callers for the same index key block while the
        leader fetches, then read the shared entry (single-flight dedupe).
        """
        cached = self.get(url, fetch_params, now=now)
        if cached is not None:
            return cached

        key = index_key(url, fetch_params)
        with self._lock:
            event = self._inflight.get(key)
            leader = event is None
            if leader:
                event = threading.Event()
                self._inflight[key] = event
        if not leader:
            # Wait for the leader's write, then re-read (bounded by their
            # put(); worst case we fall through to fetching ourselves if the
            # leader failed before storing).
            event.wait(timeout=30.0)
            cached = self.get(url, fetch_params, now=now)
            if cached is not None:
                with self._lock:
                    self._singleflight_saved += 1
                return cached

        try:
            body, content_type = fetch_fn(url)
            page = self.put(
                url,
                body,
                content_type=content_type,
                source=source,
                fetch_params=fetch_params,
                scope=scope,
                now=now,
            )
            return page
        finally:
            with self._lock:
                ev = self._inflight.pop(key, None)
                if ev is not None:
                    ev.set()

    def _evict_locked(self) -> None:
        if len(self._index) <= self._max_entries:
            return
        now = time.time()
        expired = [
            k
            for k, m in self._index.items()
            if (now - m["fetched_at"]) > self._ttl_for(m["content_type"])
        ]
        for k in expired:
            del self._index[k]
        overflow = len(self._index) - self._max_entries
        if overflow > 0:
            for k in sorted(self._index, key=lambda k: self._index[k]["fetched_at"])[:overflow]:
                del self._index[k]

    # -- invalidation -----------------------------------------------------------

    def invalidate_scope(self, scope: dict[str, Any] | list[str] | None) -> int:
        """Drop every entry captured under this scope (campaign scope change)."""
        fp = scope_fingerprint(scope)
        with self._lock:
            doomed = [k for k, m in self._index.items() if m["scope_fp"] == fp]
            for k in doomed:
                del self._index[k]
            return len(doomed)

    def invalidate_url(self, url: str, fetch_params: dict[str, Any] | None = None) -> bool:
        key = index_key(url, fetch_params)
        with self._lock:
            return self._index.pop(key, None) is not None

    # -- provenance ---------------------------------------------------------------

    def read_body(self, page: CachedPage) -> bytes:
        """Read verified page bytes back out of the artifact store."""
        with self._artifacts.open(page.digest) as reader:
            return reader.read()

    def provenance(
        self, url: str, fetch_params: dict[str, Any] | None = None
    ) -> dict[str, Any] | None:
        """Original fetch provenance for a cached page (honest-evidence view)."""
        with self._lock:
            meta = self._lookup_live(index_key(url, fetch_params), time.time())
        if meta is None:
            return None
        return {
            "url": normalize_url(url),
            "digest": meta["digest"],
            "fetched_at": meta["fetched_at"],
            "source": meta["source"],
            "content_type": meta["content_type"],
        }
