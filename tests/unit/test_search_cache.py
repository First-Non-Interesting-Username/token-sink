"""Unit tests for the search-result cache (issue #121, PLAN §9)."""

from __future__ import annotations

import threading
import time

import pytest

from search.cache import SearchResultCache, normalize_query, scope_fingerprint

SCOPE_A = {"allowed": ["https://example.com/*"]}
SCOPE_B = {"allowed": ["https://example.org/*"]}
RESULTS = [
    {"url": "https://example.com/a", "title": "A", "snippet": "first"},
    {"url": "https://example.com/b", "title": "B", "snippet": "second"},
]


def test_put_then_get_hit():
    c = SearchResultCache()
    c.put("foo bar", RESULTS, scope=SCOPE_A)
    entry = c.get("foo bar", scope=SCOPE_A)
    assert entry is not None
    assert entry.results == RESULTS
    assert entry.recorded_at  # provenance timestamp present (PLAN §9)


def test_dedup_normalizes_query():
    c = SearchResultCache()
    c.put("Foo   BAR ", RESULTS, scope=SCOPE_A)
    # Whitespace/case variants are the same logical query -> dedup hit.
    assert c.get("foo bar", scope=SCOPE_A) is not None
    assert normalize_query("  A   b ") == "a b"


def test_different_scope_no_collision():
    c = SearchResultCache()
    c.put("q", RESULTS, scope=SCOPE_A)
    assert c.get("q", scope=SCOPE_B) is None


def test_scope_order_irrelevant():
    """Same allow-set in different order must share entries, not invalidate."""
    fp1 = scope_fingerprint({"allowed": ["https://a/*", "https://b/*"]})
    fp2 = scope_fingerprint({"allow": ["https://b/*", "https://a/*"]})
    assert fp1 == fp2


def test_ttl_expiry(monkeypatch):
    c = SearchResultCache(ttl_seconds=0.05)
    c.put("q", RESULTS)
    assert c.get("q") is not None
    time.sleep(0.06)
    assert c.get("q") is None  # expired


def test_invalidate_on_scope_change():
    c = SearchResultCache()
    c.put("q1", RESULTS, scope=SCOPE_A)
    c.put("q2", RESULTS, scope=SCOPE_A)
    c.put("q3", RESULTS, scope=SCOPE_B)
    removed = c.invalidate_scope(SCOPE_A)
    assert removed == 2
    assert c.get("q1", scope=SCOPE_A) is None
    assert c.get("q2", scope=SCOPE_A) is None
    # Other scope untouched:
    assert c.get("q3", scope=SCOPE_B) is not None


def test_invalidate_query_across_limits():
    c = SearchResultCache()
    c.put("q", RESULTS, scope=SCOPE_A, limit=5)
    c.put("q", RESULTS, scope=SCOPE_A, limit=10)
    c.put("other", RESULTS, scope=SCOPE_A, limit=5)
    assert c.invalidate_query("Q ", scope=SCOPE_A) == 2  # normalized match, both limits
    # "other" survives; note limit is part of the key so we must match it.
    entry = c.get("other", scope=SCOPE_A, limit=5)
    assert entry is not None
    assert entry.results


def test_limit_is_part_of_key():
    c = SearchResultCache()
    c.put("q", RESULTS[:1], limit=5)
    entry = c.get("q", limit=10)
    assert entry is None
    assert c.get("q", limit=5).results == RESULTS[:1]


def test_max_entries_bounded():
    c = SearchResultCache(max_entries=3, ttl_seconds=60)
    for i in range(10):
        c.put(f"q{i}", RESULTS)
    stats = c.stats()
    assert stats["entries"] <= 3


def test_input_mutation_isolation():
    c = SearchResultCache()
    results = [dict(r) for r in RESULTS]
    c.put("q", results)
    results[0]["url"] = "https://mutated.example"
    entry = c.get("q")
    assert entry.results[0]["url"] == "https://example.com/a"


def test_stats_hit_rate():
    c = SearchResultCache()
    assert c.stats()["hit_rate"] == 0.0
    c.put("q", RESULTS)
    c.get("q")
    c.get("missing")
    s = c.stats()
    assert s["hits"] == 1 and s["misses"] == 1 and s["hit_rate"] == 0.5


def test_invalid_ttl_rejected():
    with pytest.raises(ValueError):
        SearchResultCache(ttl_seconds=0)


def test_concurrent_access_thread_safe():
    c = SearchResultCache(ttl_seconds=30)
    errors: list[Exception] = []

    def worker(n: int) -> None:
        try:
            for i in range(50):
                q = f"query-{i % 7}"
                if i % 3 == 0:
                    c.put(q, RESULTS, scope=SCOPE_A)
                else:
                    c.get(q, scope=SCOPE_A)
                if i % 25 == 0:
                    c.invalidate_scope(SCOPE_A)
        except Exception as e:  # pragma: no cover - collected below
            errors.append(e)

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
