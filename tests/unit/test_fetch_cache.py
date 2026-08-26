"""Fetched-page cache tests (issue #298, PLAN §9)."""

from __future__ import annotations

import threading
import time

import pytest

from search.fetch_cache import FetchCache, index_key
from storage.artifacts import ArtifactStore

NOW = 1_800_000_000.0


@pytest.fixture()
def cache(tmp_path):
    return FetchCache(ArtifactStore(tmp_path / "artifacts"))


def fetch_fn(body=b"<html>page</html>", ctype="text/html"):
    calls = {"n": 0}

    def _fetch(url: str) -> tuple[bytes, str]:
        calls["n"] += 1
        return body, ctype

    return _fetch, calls


class TestKeying:
    def test_fragments_and_case_normalize_to_one_key(self):
        assert index_key("https://X.example.com/A", None) == index_key(
            "https://x.example.com/a#section", None
        )

    def test_different_params_are_different_entries(self):
        assert index_key("http://a/", {"lang": "en"}) != index_key("http://a/", {"lang": "de"})

    def test_param_order_irrelevant(self):
        assert index_key("http://a/", {"x": 1, "y": 2}) == index_key("http://a/", {"y": 2, "x": 1})


class TestHitMissAndTTL:
    def test_miss_then_hit(self, cache):
        fn, calls = fetch_fn()
        p1 = cache.get_or_fetch("http://a/1", fn, now=NOW)
        assert not p1.from_cache and calls["n"] == 1
        p2 = cache.get("http://a/1", now=NOW + 1)
        assert p2 is not None and p2.from_cache and p2.digest == p1.digest

    def test_ttl_expiry_per_content_type(self, cache):
        cache._ttl_by_type["application/json"] = 10.0
        fn, _ = fetch_fn(b"{}", "application/json")
        cache.get_or_fetch("http://a/j", fn, now=NOW)
        assert cache.get("http://a/j", now=NOW + 5) is not None
        assert cache.get("http://a/j", now=NOW + 11) is None  # JSON expired at 10s

        fnh, _ = fetch_fn()
        cache.get_or_fetch("http://a/h", fnh, now=NOW)
        # HTML still live under default 1h TTL even after JSON expired.
        assert cache.get("http://a/h", now=NOW + 11) is not None

    def test_provenance_preserved_on_hit(self, cache):
        fn, _ = fetch_fn(b"data")
        page = cache.get_or_fetch("http://p/1", fn, source="agent-7", now=NOW)
        later = cache.get("http://p/1", now=NOW + 500)
        assert later.fetched_at == page.fetched_at == NOW  # original time kept
        assert later.source == "agent-7"
        prov = cache.provenance("http://p/1")
        assert prov is not None and prov["digest"] == page.digest and prov["fetched_at"] == NOW


class TestSingleFlight:
    def test_concurrent_fetches_dedupe_to_one_call(self, cache):
        entered = threading.Event()

        def slow_fetch(url: str) -> tuple[bytes, str]:
            # Leader is inside the fetch; hold the door briefly so the other
            # five threads pile up as waiters behind the single-flight event.
            entered.set()
            time.sleep(0.3)
            return b"shared-bytes", "text/html"

        results: list = []

        def worker():
            results.append(cache.get_or_fetch("http://s/1", slow_fetch, now=NOW))

        threads = [threading.Thread(target=worker) for _ in range(6)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        assert len(results) == 6
        assert {r.digest for r in results} == {results[0].digest}
        # Exactly one network call happened; five waiters were deduped.
        assert cache.stats()["singleflight_deduped"] == 5
        assert cache.read_body(results[0]) == b"shared-bytes"


class TestInvalidation:
    def test_scope_change_invalidates_only_that_scope(self, cache):
        scope_a = ["https://a.example.com/*"]
        scope_b = ["https://b.example.com/*"]
        fna, _ = fetch_fn()
        fnb, _ = fetch_fn(b"B")
        cache.put("http://a/1", b"A", scope=scope_a, now=NOW)
        cache.put("http://b/1", b"B", scope=scope_b, now=NOW)
        assert cache.invalidate_scope(scope_a) == 1
        assert cache.get("http://a/1", now=NOW + 1) is None
        assert cache.get("http://b/1", now=NOW + 1) is not None  # other scope untouched

    def test_invalidate_url(self, cache):
        fn, _ = fetch_fn()
        cache.get_or_fetch("http://i/1", fn, now=NOW)
        assert cache.invalidate_url("http://i/1") is True
        assert cache.invalidate_url("http://i/1") is False


class TestMetrics:
    def test_hit_rate_and_bandwidth_saved(self, cache):
        fn, _ = fetch_fn(b"12345")
        cache.get_or_fetch("http://m/1", fn, now=NOW)
        cache.get("http://m/1", now=NOW + 1)
        cache.get("http://m/1", now=NOW + 2)
        cache.get("http://missing/", now=NOW + 3)
        s = cache.stats()
        assert s["hits"] == 2 and s["misses"] == 2  # initial get_or_fetch miss + missing URL
        assert s["hit_rate"] == pytest.approx(2 / 4)
        assert s["bandwidth_saved_bytes"] == 10  # 5 bytes x 2 hits
