"""Tests for the URL scope filter (PLAN §9, issue #103).

Covers: basic in/out/unlisted classification, subdomain and URL-prefix
matching, CIDR entries for IP targets, scheme allowlisting, userinfo tricks,
trailing-dot FQDNs, IDN/punycode lookalikes, port variations, default-deny
behavior, per-hop redirect-chain re-checks, and private-IP rebinding blocks.
"""

import pytest

from policy.url_filter import ScopeVerdict, UrlScopeFilter


@pytest.fixture()
def filt():
    return UrlScopeFilter(
        in_scope=["example.com", "https://api.example.com/v2"],
        out_of_scope=["admin.example.com", "https://example.com/private"],
    )


def v(c):
    return c.verdict


# --- basic classification ----------------------------------------------------


def test_in_scope_domain(filt):
    assert v(filt.check("https://example.com/")) is ScopeVerdict.IN_SCOPE


def test_subdomains_included_for_domain_entries(filt):
    assert v(filt.check("https://blog.example.com/post")) is ScopeVerdict.IN_SCOPE


def test_similar_but_different_domain_is_ambiguous(filt):
    # notexample.com ends with example.com as a string but is NOT a subdomain.
    c = filt.check("https://notexample.com/")
    assert v(c) is ScopeVerdict.AMBIGUOUS  # default-deny on unlisted


def test_out_of_scope_subdomain_wins_over_wildcard(filt):
    c = filt.check("https://admin.example.com/panel")
    assert v(c) is ScopeVerdict.OUT_OF_SCOPE
    assert "admin.example.com" in c.reason


def test_out_of_scope_path_prefix_beats_domain_entry(filt):
    c = filt.check("https://example.com/private/x")
    assert v(c) is ScopeVerdict.OUT_OF_SCOPE


def test_url_prefix_match(filt):
    assert v(filt.check("https://api.example.com/v2/users")) is ScopeVerdict.IN_SCOPE


def test_url_prefix_does_not_leak_to_sibling_paths():
    # With ONLY a prefix entry covering api.example.com/v2, sibling paths
    # like /v22 must not match — prefix matching is segment-aware.
    f = UrlScopeFilter(in_scope=["https://api.example.com/v2"])
    assert v(f.check("https://api.example.com/v22/users")) is ScopeVerdict.AMBIGUOUS
    assert v(f.check("https://api.example.com/v2/users")) is ScopeVerdict.IN_SCOPE


def test_unlisted_host_default_denied_with_actionable_reason(filt):
    c = filt.check("https://random.org/x")
    assert v(c) is ScopeVerdict.AMBIGUOUS
    assert "not listed" in c.reason


# --- scheme restrictions ------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "ftp://example.com/x",
        "file:///etc/passwd",
        "javascript://example.com/%0aalert(1)",
        "gopher://example.com",
    ],
)
def test_non_http_schemes_refused(filt, url):
    assert v(filt.check(url)) is ScopeVerdict.OUT_OF_SCOPE


# --- tricky host forms (issue acceptance criteria) ----------------------------


def test_trailing_dot_fqdn_matches(filt):
    # `example.com.` is the same FQDN; a trailing dot must not bypass scope.
    assert v(filt.check("https://example.com./")) is ScopeVerdict.IN_SCOPE
    # ...and must not sneak into an out-of-scope carve-out either way:
    assert v(filt.check("https://admin.example.com./x")) is ScopeVerdict.OUT_OF_SCOPE


def test_case_insensitive_host(filt):
    assert v(filt.check("https://EXAMPLE.COM/Page")) is ScopeVerdict.IN_SCOPE
    assert v(filt.check("https://ADMIN.EXAMPLE.COM/x")) is ScopeVerdict.OUT_OF_SCOPE


def test_userinfo_smuggling_refused(filt):
    # The true hostname here is evil.host; visually it looks like example.com.
    c = filt.check("https://example.com@evil.host/")
    assert v(c) is ScopeVerdict.OUT_OF_SCOPE
    assert "credentials" in c.reason


def test_idn_homoglyph_not_matched_by_ascii_scope(filt):
    # xn--pple-43d.com decodes to æpple.com — clearly not example.com, so the
    # classifier must NOT bless it just because its punycode form looks close.
    c = filt.check("https://xn--pple-43d.com/")
    assert v(c) is ScopeVerdict.AMBIGUOUS


def test_unicode_idn_scope_entry_matches_punycode_url():
    f = UrlScopeFilter(in_scope=["exämple.com"])
    # Same domain on the wire: punycode form of the URL must match the
    # Unicode scope entry after decoding.
    assert v(f.check("https://xn--exmple-cua.com/")) is ScopeVerdict.IN_SCOPE


def test_port_variation_still_classified_by_host(filt):
    assert v(filt.check("https://example.com:8443/app")) is ScopeVerdict.IN_SCOPE


def test_port_does_not_defeat_out_of_scope(filt):
    assert v(filt.check("https://admin.example.com:8443/")) is ScopeVerdict.OUT_OF_SCOPE


def test_fragment_ignored(filt):
    assert v(filt.check("https://example.com/#frag")) is ScopeVerdict.IN_SCOPE


# --- CIDR entries --------------------------------------------------------------


def test_cidr_entry_matches_ip_literal():
    f = UrlScopeFilter(in_scope=["10.0.0.0/8"])
    assert v(f.check("http://10.1.2.3/x")) is ScopeVerdict.IN_SCOPE
    assert v(f.check("http://11.0.0.1/x")) is ScopeVerdict.AMBIGUOUS


# --- redirect chains ------------------------------------------------------------


def test_chain_all_in_scope(filt):
    c = filt.check_redirect_chain(["https://example.com/a", "https://example.com/b"])
    assert v(c) is ScopeVerdict.IN_SCOPE


def test_chain_hop_to_out_of_scope_blocked(filt):
    c = filt.check_redirect_chain(["https://example.com/a", "https://admin.example.com/b"])
    assert v(c) is ScopeVerdict.OUT_OF_SCOPE
    assert c.hop_index == 1


def test_chain_hop_to_unlisted_host_refused(filt):
    # Unlisted ≠ allowed: default-deny applies per hop too.
    c = filt.check_redirect_chain(["https://example.com/a", "https://evil.host/b"])
    assert v(c) is ScopeVerdict.AMBIGUOUS
    assert c.hop_index == 1


def test_first_hop_failure_reports_hop_zero(filt):
    c = filt.check_redirect_chain(["https://offscope.net/start", "https://example.com/"])
    assert v(c) is ScopeVerdict.AMBIGUOUS
    assert c.hop_index == 0


def test_rebinding_private_resolution_blocks_even_in_scope_name(filt):
    # A name that IS in scope but resolves private must be blocked at the hop.
    c = filt.check_redirect_chain(
        ["https://example.com/", "https://internal.example.com/next"],
        private_ip_hosts=frozenset({"internal.example.com"}),
    )
    assert v(c) is ScopeVerdict.OUT_OF_SCOPE
    assert "private" in c.reason


def test_empty_chain_ambiguous(filt):
    assert v(filt.check_redirect_chain([])) is ScopeVerdict.AMBIGUOUS
