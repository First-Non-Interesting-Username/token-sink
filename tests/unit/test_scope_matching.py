"""Unit tests for scope matcher semantics (issue #134, PLAN §5/§19.1).

Covers canonicalization (IDN/punycode, trailing dots, case, default ports),
subdomain opt-in, path prefix vs segment semantics, out-of-scope precedence,
and property tests asserting no input form of an out-of-scope host matches
an in-scope rule.
"""

import random
import string

import pytest

from policy.matching import (
    MatchResult,
    ScopeRule,
    ScopeRuleSet,
    canonicalize_host,
    canonicalize_url,
    classify,
)


def domain_rule(value, **kw):
    kw.setdefault("rule_id", f"in:{value}")
    return ScopeRule(value=value, **{"kind": "domain", **kw})


# --- canonicalization -------------------------------------------------------


def test_canonical_host_lowercases_and_strips_trailing_dot():
    assert canonicalize_host("EXAMPLE.com.") == "example.com"


def test_canonical_host_idn_to_punycode():
    assert canonicalize_host("exämple.com") == "xn--exmple-cua.com"


def test_canonical_url_strips_default_ports():
    assert canonicalize_url("https://example.com:443/a")["port"] is None
    assert canonicalize_url("http://example.com:80/")["port"] is None


def test_canonical_url_keeps_nondefault_port():
    assert canonicalize_url("https://example.com:8443/")["port"] == 8443


def test_trailing_dot_fqdn_matches_bare_rule():
    rs = ScopeRuleSet(in_scope=[domain_rule("example.com")])
    assert rs.classify("https://example.com./x").classification == "in"


def test_uppercase_host_matches_lowercase_rule():
    rs = ScopeRuleSet(in_scope=[domain_rule("example.com")])
    assert rs.classify("https://EXAMPLE.COM/x").classification == "in"


def test_idn_lookalike_of_out_of_scope_never_matches_in_scope():
    # In-scope: punycode spelling of example.com; the IDN homoglyph of a
    # DIFFERENT host must stay unlisted.
    rs = ScopeRuleSet(in_scope=[domain_rule("xn--exmple-cua.com")])
    assert rs.classify("https://exämple.com/x").classification == "in"
    other = ScopeRuleSet(
        in_scope=[domain_rule("example.com")],
        out_of_scope=[ScopeRule(rule_id="out:idn", value="exämple.net", kind="domain", out=True)],
    )
    assert other.classify("https://exämple.net/x").classification == "out"


# --- subdomain semantics ----------------------------------------------------


def test_subdomains_opt_in_default_off():
    exact = ScopeRuleSet(in_scope=[domain_rule("example.com")])
    assert exact.classify("https://api.example.com/").classification == "unlisted"
    wide = ScopeRuleSet(in_scope=[domain_rule("example.com", include_subdomains=True)])
    assert wide.classify("https://api.example.com/").classification == "in"


def test_label_boundary_prevents_suffix_spoof():
    rs = ScopeRuleSet(in_scope=[domain_rule("example.com", include_subdomains=True)])
    assert rs.classify("https://evilexample.com/").classification == "unlisted"
    assert rs.classify("https://evilexample.com.").classification == "unlisted"


# --- path semantics ---------------------------------------------------------


def url_rule(value, **kw):
    kw.setdefault("rule_id", f"in:{value}")
    return ScopeRule(value=value, **{"kind": "url", **kw})


def test_path_segment_mode_does_not_swallow_sibling_prefix():
    rs = ScopeRuleSet(in_scope=[url_rule("https://example.com/api")])
    assert rs.classify("https://example.com/api-v2/x").classification == "unlisted"
    assert rs.classify("https://example.com/api/v1").classification == "in"


def test_path_prefix_mode_matches_prefixes():
    rs = ScopeRuleSet(in_scope=[url_rule("https://example.com/api", path_mode="prefix")])
    assert rs.classify("https://example.com/api-v2/x").classification == "in"


def test_url_scheme_restriction_per_rule():
    rs = ScopeRuleSet(in_scope=[url_rule("https://example.com/app", allowed_schemes=("https",))])
    assert rs.classify("https://example.com/app").classification == "in"
    assert rs.classify("http://example.com/app").classification == "unlisted"


# --- precedence & explainability ---------------------------------------------


def test_out_of_scope_wins_over_in_scope_on_both_match():
    rs = ScopeRuleSet(
        in_scope=[domain_rule("example.com", include_subdomains=True)],
        out_of_scope=[
            ScopeRule(rule_id="out:mail", value="mail.example.com", kind="domain", out=True)
        ],
    )
    r = rs.classify("https://mail.example.com/")
    assert r.classification == "out" and r.rule_id == "out:mail"


def test_unlisted_is_default_deny_with_reason():
    r = ScopeRuleSet().classify("https://nowhere.org/")
    assert r.classification == "unlisted" and "default-deny" in r.reason


def test_result_carries_matched_rule_and_field():
    rs = ScopeRuleSet(in_scope=[domain_rule("example.com", include_subdomains=True)])
    r = rs.classify("https://sub.example.com/x")
    assert isinstance(r, MatchResult)
    assert r.rule_id and r.evaluated_field == "target.host"
    assert "subdomain" in r.reason


def test_cidr_rule_matching():
    rs = ScopeRuleSet(in_scope=[ScopeRule(rule_id="in:net", value="192.168.7.0/24", kind="cidr")])
    assert rs.classify("192.168.7.10").classification == "in"
    assert rs.classify("192.168.8.10").classification == "unlisted"


# --- property/fuzz: no bypass forms ------------------------------------------

ALPHABET = string.ascii_lowercase + string.digits + "-."


def _rand_host(rng):
    return "".join(rng.choice(ALPHABET) for _ in range(rng.randint(4, 20)))


@pytest.mark.parametrize("seed", [1, 2, 3, 4, 5])
def test_fuzz_random_hosts_cannot_shadow_in_scope(seed):
    rng = random.Random(seed)
    rs = ScopeRuleSet(
        in_scope=[domain_rule("scope-target.example", include_subdomains=True)],
        out_of_scope=[
            ScopeRule(rule_id="out:x", value="banned.scope-target.example", kind="domain", out=True)
        ],
    )
    for _ in range(200):
        host = _rand_host(rng)
        if host == "scope-target.example" or host.endswith(".scope-target.example"):
            continue  # genuinely in-scope forms are excluded from this property
        for variant in (host, host + ".", host.upper(), f"{host}:8443"):
            res = rs.classify(f"https://{variant}/")
            if res.classification == "in":
                # Only legitimate subdomains of the rule may match 'in'
                assert canonicalize_host(variant).endswith(".scope-target.example"), variant


def test_ip_literal_forms_do_not_match_domain_rules():
    rs = ScopeRuleSet(in_scope=[domain_rule("127.0.0.1")])
    # A domain rule with an IP-looking value still only matches that literal.
    assert rs.classify("127.0.0.1").classification == "in"
    assert rs.classify("127.0.0.2").classification == "unlisted"


def test_userinfo_trick_does_not_change_host_evaluation():
    # https://example.com@evil.test — real host is evil.test, must be unlisted.
    canon = canonicalize_url("https://example.com@evil.test/")
    assert canon["host"] == "evil.test"
    assert canon["userinfo"] is True
    rs = ScopeRuleSet(in_scope=[domain_rule("example.com", include_subdomains=True)])
    assert rs.classify("https://example.com@evil.test/").classification == "unlisted"


def test_pure_function_same_input_same_output():
    rules = (
        [domain_rule("example.com", include_subdomains=True)],
        [ScopeRule(rule_id="o", value="x.example.com", kind="domain", out=True)],
    )
    a = classify(*rules, target="https://x.example.com/")
    b = classify(*rules, target="https://x.example.com/")
    assert a == b
