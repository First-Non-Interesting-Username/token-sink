"""Unit tests for search/fetch_policy.py (issue #300, PLAN §9/§15)."""

from search.fetch_policy import FetchPermission, FetchPolicy, RobotsCache, TosPolicy


def make_cache(status=200, lines=None, ttl=3600.0):
    lines = lines if lines is not None else ["User-agent: *", "Allow: /"]
    loader = lambda host: (status, b"x" if status == 200 else None, lines)  # noqa: E731
    t = [0.0]
    return RobotsCache(ttl_seconds=ttl, loader=loader, clock=lambda: t[0]), t


def test_robots_allows_open_site():
    cache, _ = make_cache()
    p = FetchPolicy(robots=cache)
    out = p.check("https://example.com/page")
    assert isinstance(out, FetchPermission)
    assert out.allowed and out.source == "robots_allow"


def test_robots_disallow_blocks():
    cache, _ = make_cache(lines=["User-agent: *", "Disallow: /private"])
    p = FetchPolicy(robots=cache)
    out = p.check("https://example.com/private/x")
    assert not out.allowed and out.source == "robots_disallow"


def test_robots_4xx_means_unrestricted():
    cache, _ = make_cache(status=404)
    p = FetchPolicy(robots=cache)
    assert p.check("https://example.com/any").allowed


def test_robots_5xx_fails_closed():
    cache, _ = make_cache(status=503)
    p = FetchPolicy(robots=cache)
    out = p.check("https://example.com/any")
    assert not out.allowed and out.source == "conservative_deny"


def test_override_grants_on_deny_but_is_recorded():
    cache, _ = make_cache(lines=["User-agent: *", "Disallow: /"])
    p = FetchPolicy(robots=cache)
    out = p.check("https://example.com/x", authorized_override=True)
    assert out.allowed and out.override_used and out.source == "override"


def test_tos_block_cannot_be_beaten_without_override():
    cache, _ = make_cache()
    p = FetchPolicy(robots=cache, tos_by_host={"example.com": TosPolicy(no_automated_fetch=True)})
    out = p.check("https://example.com/page")
    assert not out.allowed and out.source == "tos"
    out2 = p.check("https://example.com/page", authorized_override=True)
    assert out2.allowed and out2.override_used


def test_purpose_restriction():
    cache, _ = make_cache()
    p = FetchPolicy(
        robots=cache,
        tos_by_host={"example.com": TosPolicy(allowed_purposes={"search"})},
    )
    assert p.check("https://example.com/p", purpose="search").allowed
    out = p.check("https://example.com/p", purpose="poc_reproduction")
    assert not out.allowed and out.source == "tos"


def test_ttl_cache_does_not_refetch_within_window():
    calls = []

    def loader(host):
        calls.append(host)
        return 200, b"", ["User-agent: *", "Allow: /"]

    t = [0.0]
    cache = RobotsCache(ttl_seconds=100.0, loader=loader, clock=lambda: t[0])
    policy = FetchPolicy(robots=cache)
    policy.check("https://a.example/1")
    t[0] = 50.0  # within TTL
    policy.check("https://a.example/2")
    assert len(calls) == 1
    t[0] = 200.0  # past TTL → refetch
    policy.check("https://a.example/3")
    assert len(calls) == 2


def test_no_hostname_denied():
    p = FetchPolicy()
    out = p.check("not a url")
    assert not out.allowed and out.source == "conservative_deny"


def test_specific_agent_rules_respected():
    lines = [
        "User-agent: token-sink-agent",
        "Disallow: /agent-blocked",
        "User-agent: *",
        "Allow: /",
    ]
    cache, _ = make_cache(lines=lines)
    p = FetchPolicy(robots=cache)
    assert not p.check("https://example.com/agent-blocked").allowed
