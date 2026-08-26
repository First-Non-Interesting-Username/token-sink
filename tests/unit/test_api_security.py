"""Tests for local web-UI security hardening (issue #152)."""

from api.security import (
    check_host,
    check_origin,
    check_token,
    generate_session_token,
    guard_request,
)

TOK = generate_session_token()


def test_token_is_per_launch_and_random():
    assert TOK != generate_session_token()
    assert len(TOK) >= 32


def test_dns_rebinding_host_rejected():
    v = check_host("evil.example.com")
    assert not v.allowed and v.status == 403
    assert check_host("127.0.0.1:8741").allowed
    assert check_host("localhost").allowed
    assert check_host(None).status == 400


def test_cross_origin_post_rejected_get_allowed():
    assert not check_origin("POST", "https://attacker.example").allowed
    # same-origin (loopback) is fine
    assert check_origin("POST", "http://127.0.0.1:8080").allowed
    assert check_origin("POST", "http://localhost:3000").allowed
    # GETs are never Origin-gated (must be side-effect free by contract)
    assert check_origin("GET", "https://attacker.example").allowed


def test_missing_origin_policy_configurable():
    assert check_origin("POST", None, allow_missing_origin=True).allowed
    assert not check_origin("POST", None, allow_missing_origin=False).allowed


def test_bearer_token_required_on_mutations_only():
    auth = f"Bearer {TOK}"
    assert check_token("POST", auth, TOK).allowed
    assert check_token("DELETE", auth, TOK).allowed
    assert check_token("GET", None, TOK).allowed  # GET unauthenticated
    assert check_token("POST", None, TOK).status == 401
    assert check_token("POST", "Bearer wrong", TOK).status == 401
    assert check_token("POST", TOK, TOK).status == 401  # header prefix required


def test_rotation_invalidates_old_sessions():
    old = "stale-token-from-last-launch"
    assert check_token("PATCH", f"Bearer {old}", TOK).status == 401


def test_guard_request_composes_all_checks():
    good = {
        "Host": "127.0.0.1:9000",
        "Authorization": f"Bearer {TOK}",
    }
    assert guard_request("POST", good, expected_token=TOK).allowed

    rebinding = dict(good, Host="attacker.example")
    assert not guard_request("POST", rebinding, expected_token=TOK).allowed

    no_token = {"Host": "127.0.0.1:9000"}
    v = guard_request("POST", no_token, expected_token=TOK)
    assert not v.allowed and v.status == 401

    # non-mutating request passes without a token
    assert guard_request("GET", {"Host": "127.0.0.1"}, expected_token=TOK).allowed
