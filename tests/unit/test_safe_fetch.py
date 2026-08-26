"""Tests for the fetch-time URL safety pipeline (issue #124, PLAN §9/§15).

Each bypass class named in the issue gets explicit cases: redirect-to-private,
DNS-rebinding simulation via a mocked resolver, decimal/octal IPv4 encodings,
and IPv6-mapped IPv4.
"""

import pytest

from policy.scope import ScopePolicy, TargetSpec
from policy.ssrf import SSRFGuard
from search.safe_fetch import (
    FetchLimits,
    SafeFetchPolicy,
    normalize_host_for_check,
    normalize_ipv4_shorthand,
)


def make_scope():
    return ScopePolicy(
        campaign_uuid="123e4567-e89b-42d3-a456-426614174000",
        in_scope=[TargetSpec("example.com"), TargetSpec("10.77.0.0/16", kind="cidr")],
        out_of_scope=[TargetSpec("mail.example.com")],
    )


@pytest.fixture
def make_policy():
    def _make(scope=None, resolver=None):
        ssrf = (
            SSRFGuard(resolver=resolver)
            if resolver
            else SSRFGuard(
                resolver=lambda host: ["93.184.216.34"]  # public example.com address
            )
        )
        return SafeFetchPolicy(scope=scope if scope is not None else make_scope(), ssrf=ssrf)

    return _make


# --- URL validation ----------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "file:///etc/passwd",
        "gopher://example.com",
        "ftp://example.com/pub",
        "javascript:alert(1)",
    ],
)
def test_dangerous_schemes_blocked(make_policy, url):
    assert not make_policy().check_url(url).ok


def test_userinfo_rejected(make_policy):
    assert not make_policy().check_url("https://user:pass@example.com/").ok


def test_https_in_scope_allowed(make_policy):
    v = make_policy().check_url("https://api.example.com/v1/status")
    assert v.ok, v.reason


def test_unlisted_destination_refused_not_guessed(make_policy):
    # 'unlisted' is refused — missing scope is never resolved by guessing.
    v = make_policy().check_url("https://not-in-scope.org/")
    assert not v.ok
    assert "unlisted" in v.reason


def test_out_of_scope_wins_over_wildcard(make_policy):
    assert not make_policy().check_url("https://mail.example.com/").ok


# --- IPv4 shorthand encodings -------------------------------------------------


@pytest.mark.parametrize(
    "shorthand,expected",
    [
        ("2130706433", "127.0.0.1"),
        ("0x7f.0.0.1", "127.0.0.1"),
        ("0177.0.0.1", "127.0.0.1"),
        ("127.1", "127.0.0.1"),
        ("0x7f000001", "127.0.0.1"),
    ],
)
def test_shorthand_normalization(shorthand, expected):
    assert normalize_ipv4_shorthand(shorthand) == expected


def test_decimal_loopback_blocked(make_policy):
    # http://2130706433/ is 127.0.0.1 — must not pass as a "public" host.
    v = make_policy().check_url("http://2130706433/")
    assert not v.ok


def test_hex_octal_loopback_blocked(make_policy):
    assert not make_policy().check_url("http://0x7f.0.0.1/").ok
    assert not make_policy().check_url("http://0177.0.0.1/").ok


def test_short_form_loopback_blocked(make_policy):
    assert not make_policy().check_url("http://127.1/").ok


# --- IPv6 ---------------------------------------------------------------------


def test_ipv6_loopback_blocked(make_policy):
    assert not make_policy().check_url("http://[::1]/").ok


def test_ipv6_mapped_ipv4_private_blocked(make_policy):
    # ::ffff:10.0.0.1 must be judged by its IPv4 side.
    assert normalize_host_for_check("http://[::ffff:10.0.0.1]/") == "10.0.0.1"
    assert not make_policy().check_url("http://[::ffff:10.0.0.1]/").ok


def test_metadata_service_blocked_by_name(make_policy):
    # Even if it somehow resolved publicly, the name itself is blocked.
    v = SafeFetchPolicy(
        scope=make_scope(),
        ssrf=SSRFGuard(resolver=lambda h: ["8.8.8.8"]),
    ).check_url("http://metadata.google.internal/")
    assert not v.ok


# --- DNS rebinding (mocked resolver) ------------------------------------------


def test_dns_rebind_to_private_blocked():
    def rebinding_resolver(host):
        # First answer public, second private — fail-closed on ANY private answer.
        return ["93.184.216.34", "192.168.1.50"]

    policy = SafeFetchPolicy(
        scope=make_scope(),
        ssrf=SSRFGuard(resolver=rebinding_resolver),
    )
    v = policy.check_url("https://rebinding.example.com/")
    assert not v.ok
    assert "private" in v.reason or "rebind" in v.reason.lower()


def test_resolved_addresses_exposed_for_pinning():
    policy = SafeFetchPolicy(
        scope=make_scope(),
        ssrf=SSRFGuard(resolver=lambda h: ["93.184.216.34"]),
    )
    v = policy.check_url("https://example.com/")
    assert v.ok
    assert v.resolved_addresses == ["93.184.216.34"]


# --- redirects -----------------------------------------------------------------


def test_redirect_to_public_same_site_ok(make_policy):
    v = make_policy().check_redirect_chain("https://example.com/a", ["https://www.example.com/b"])
    assert v.ok, v.reason


def test_redirect_to_private_blocked(make_policy):
    v = make_policy().check_redirect_chain(
        "https://example.com/a", ["http://169.254.169.254/latest/meta-data/"]
    )
    assert not v.ok
    assert "hop 1" in v.reason


def test_redirect_to_out_of_scope_blocked(make_policy):
    v = make_policy().check_redirect_chain(
        "https://example.com/a", ["https://mail.example.com/inbox"]
    )
    assert not v.ok


def test_redirect_hop_cap(make_policy):
    policy = make_policy()
    chain = [f"https://example.com/hop{i}" for i in range(20)]
    v = policy.check_redirect_chain("https://example.com/start", chain)
    assert not v.ok
    assert "hops" in v.reason


def test_relative_redirect_resolved_and_checked(make_policy):
    v = make_policy().check_redirect_chain(
        "https://example.com/dir/page", ["/other", "https://169.254.169.254/"]
    )
    assert not v.ok


# --- response limits ------------------------------------------------------------


def test_content_type_allowlist(make_policy):
    ok, why = make_policy().response_allowed("text/html; charset=utf-8", 100, 0.1)
    assert ok
    ok, why = make_policy().response_allowed("application/octet-stream", 100, 0.1)
    assert not ok


def test_max_size_enforced(make_policy):
    ok, _ = make_policy().response_allowed("text/html", FetchLimits().max_bytes + 1, 0.1)
    assert not ok


def test_timeout_budget(make_policy):
    ok, why = make_policy().response_allowed("text/html", 10, FetchLimits().timeout_seconds * 2)
    assert not ok
    assert "budget" in why
