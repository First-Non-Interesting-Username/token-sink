"""Search-result cache: dedup, TTL, and scope-change invalidation (PLAN §9).

Why a dedicated cache layer instead of memoizing inside callers:
- Search calls hit external providers (ddgs) that are slow, rate-limited,
  and non-deterministic; caching is the cheapest way to honor PLAN §9's
  "query deduplication ... and caching" requirement without hammering them.
- Scope changes must invalidate results immediately (a cached URL that was
  in-scope yesterday may be out-of-scope today), so invalidation is a
  first-class operation here rather than an afterthought.

Design notes:
- Cache key = normalized query + scope fingerprint + limit. Two agents asking
  the same question under the same scope share one entry (dedup); the same
  query under a different scope does NOT.
- TTL expiry is lazy (checked on read). A background sweeper is unnecessary
  for Phase 1 and would add concurrency complexity; expired entries are
  dropped on read and purged opportunistically on write/invalidation.
- Entries record provenance (query, timestamp, source status) per PLAN §9's
  record-keeping requirements so audit trails survive cache hits.
"""

from __future__ import annotations

import hashlib
import json
import re
import threading
import time
from dataclasses import dataclass, field
from datetime import UTC
from typing import Any


def normalize_query(query: str) -> str:
    """Normalize a search query for dedup purposes.

    Whitespace-collapsed and case-folded so 'Foo  Bar' and 'foo bar' are one
    logical query — external engines treat them identically anyway.
    """
    return re.sub(r"\s+", " ", query.strip()).casefold()


def scope_fingerprint(scope: dict[str, Any] | list[str] | tuple[str, ...] | None) -> str:
    """Stable fingerprint of a scope definition.

    Accepts either a list/tuple of allowed-URL patterns or a scope dict with
    an 'allowed' / 'allow' key. The fingerprint changes whenever the allowed
    set changes in a way that could change which URLs are in-scope, which is
    what drives invalidation on scope change.
    """
    if scope is None:
        patterns: list[str] = []
    elif isinstance(scope, dict):
        raw = scope.get("allowed", scope.get("allow", []))
        patterns = [str(p) for p in raw]
    else:
        patterns = [str(p) for p in scope]
    # Sort before hashing: order of allow-patterns is semantically irrelevant,
    # and sorting prevents spurious invalidation when callers rebuild the list.
    canonical = json.dumps(sorted(patterns), separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


@dataclass
class CacheEntry:
    """One cached search-result set plus its PLAN §9 provenance fields."""

    results: list[dict[str, Any]]
    created_at: float  # monotonic clock, for TTL math only
    recorded_at: str  # wall-clock UTC ISO string, for audit/provenance
    hits: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)


class SearchResultCache:
    """Thread-safe in-memory TTL cache keyed by (query, scope, limit).

    Not persistent by design for Phase 1: search results are cheap to refetch
    after a restart and persistence would couple this to the Storage schema
    before the search subsystem itself has landed. Revisit if profiling shows
    restart warm-up cost matters.
    """

    def __init__(self, ttl_seconds: float = 900.0, max_entries: int = 512):
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        if max_entries < 1:
            raise ValueError("max_entries must be >= 1")
        self._ttl = float(ttl_seconds)
        self._max_entries = max_entries
        self._entries: dict[str, CacheEntry] = {}
        # One lock guards both the dict and hit/miss counters; contention is
        # irrelevant at expected call rates and correctness beats sharding.
        self._lock = threading.Lock()
        self._hits = 0
        self._misses = 0

    def _key(self, query: str, scope_fp: str, limit: int) -> str:
        return f"{scope_fp}:{limit}:{normalize_query(query)}"

    def get(
        self,
        query: str,
        scope: dict[str, Any] | list[str] | None = None,
        limit: int = 10,
    ) -> CacheEntry | None:
        """Return a live (non-expired) entry, or None on miss/expiry."""
        key = self._key(query, scope_fingerprint(scope), limit)
        now = time.monotonic()
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                self._misses += 1
                return None
            if now - entry.created_at > self._ttl:
                # Lazy eviction: drop here so the next read doesn't repeat
                # the expiry check on a dead entry.
                del self._entries[key]
                self._misses += 1
                return None
            entry.hits += 1
            self._hits += 1
            return entry

    def put(
        self,
        query: str,
        results: list[dict[str, Any]],
        scope: dict[str, Any] | list[str] | None = None,
        limit: int = 10,
        recorded_at: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Store a result set. Copies inputs so later caller mutations can't
        corrupt what a concurrent reader sees."""
        from datetime import datetime

        if recorded_at is None:
            recorded_at = datetime.now(UTC).isoformat()
        key = self._key(query, scope_fingerprint(scope), limit)
        entry = CacheEntry(
            results=[dict(r) for r in results],
            created_at=time.monotonic(),
            recorded_at=recorded_at,
            metadata=dict(metadata or {}),
        )
        with self._lock:
            self._entries[key] = entry
            self._evict_locked()

    def _evict_locked(self) -> None:
        """Keep size bounded: purge expired first, then oldest-inserted."""
        if len(self._entries) <= self._max_entries:
            return
        now = time.monotonic()
        expired = [k for k, e in self._entries.items() if now - e.created_at > self._ttl]
        for k in expired:
            del self._entries[k]
        overflow = len(self._entries) - self._max_entries
        if overflow > 0:
            # Oldest-created entries first; insertion order is fine as a
            # proxy since we don't do LRU bookkeeping on get().
            for k in sorted(self._entries, key=lambda k: self._entries[k].created_at)[:overflow]:
                del self._entries[k]

    def invalidate_scope(self, scope: dict[str, Any] | list[str] | None) -> int:
        """Drop every entry cached under this exact scope definition.

        Callers MUST invoke this whenever the scope's allow-list changes;
        keeping stale results around would let out-of-scope URLs flow into
        downstream actions. Returns number of entries removed.
        """
        fp = scope_fingerprint(scope)
        with self._lock:
            doomed = [k for k in self._entries if k.startswith(fp + ":")]
            for k in doomed:
                del self._entries[k]
            return len(doomed)

    def invalidate_query(self, query: str, scope: dict[str, Any] | list[str] | None = None) -> int:
        """Drop all entries for a query under a scope (any limit variant)."""
        fp = scope_fingerprint(scope)
        norm = normalize_query(query)
        with self._lock:
            doomed = [
                k
                for k in self._entries
                if k.split(":", 2)[2] == norm and (fp == "" or k.startswith(fp + ":"))
            ]
            for k in doomed:
                del self._entries[k]
            return len(doomed)

    def clear(self) -> int:
        """Drop everything. Returns number of entries removed."""
        with self._lock:
            n = len(self._entries)
            self._entries.clear()
            return n

    def stats(self) -> dict[str, Any]:
        """Hit/miss counters for observability (PLAN §13 style metrics)."""
        with self._lock:
            live = sum(
                1 for e in self._entries.values() if time.monotonic() - e.created_at <= self._ttl
            )
            return {
                "entries": live,
                "hits": self._hits,
                "misses": self._misses,
                "hit_rate": (
                    self._hits / (self._hits + self._misses) if (self._hits + self._misses) else 0.0
                ),
            }
