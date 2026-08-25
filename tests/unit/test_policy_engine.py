"""Unit tests for the scope model and policy engine (PLAN §5, §19.1)."""

from policy.engine import PolicyEngine, ScopeStatus, ToolCallRequest
from policy.scope import RateLimit, ScopePolicy, TargetSpec


def make_scope(**overrides) -> ScopePolicy:
    defaults = dict(
        campaign_uuid="c-1",
        program_name="Hack Club Security",
        authorization_reference="auth-ref-001",
        in_scope=[TargetSpec("example.com")],
        out_of_scope=[TargetSpec("mail.example.com")],
        allowed_methods={"GET", "POST"},
        allowed_test_classes={"vulnerability_scanning"},
        active_testing_enabled=True,
    )
    defaults.update(overrides)
    return ScopePolicy(**defaults)


def req(**kw) -> ToolCallRequest:
    defaults = dict(tool="http_fetch", agent_uuid="a-1", campaign_uuid="c-1")
    defaults.update(kw)
    return ToolCallRequest(**defaults)


# --- scope classification ---------------------------------------------------


def test_domain_target_matches_subdomains():
    scope = make_scope()
    assert scope.classify_target("https://example.com/x")[0] == "in"
    assert scope.classify_target("https://api.example.com/")[0] == "in"


def test_explicit_out_of_scope_wins():
    scope = make_scope()
    assert scope.classify_target("https://mail.example.com/")[0] == "out"


def test_unlisted_is_default_deny_classification():
    scope = make_scope()
    assert scope.classify_target("https://evil.net/")[0] == "unlisted"


def test_url_prefix_target():
    scope = make_scope(in_scope=[TargetSpec("https://example.com/api", kind="url")])
    assert scope.classify_target("https://example.com/api/v1")[0] == "in"
    assert scope.classify_target("https://example.com/other")[0] == "unlisted"


def test_cidr_target():
    scope = make_scope(
        in_scope=[TargetSpec("192.168.7.0/24", kind="cidr")],
        out_of_scope=[],
        authorization_reference="lab",
    )
    assert scope.classify_target("http://192.168.7.10/")[0] == "in"
    assert scope.classify_target("http://192.168.8.10/")[0] == "unlisted"


def test_rate_limit_model_stores_per_target():
    scope = make_scope(rate_limits={"example.com": RateLimit(30, 60)})
    assert scope.rate_limits["example.com"].max_requests == 30


# --- engine -----------------------------------------------------------------


def test_missing_scope_blocks_everything():
    engine = PolicyEngine(None)
    d = engine.evaluate(req(target="https://example.com/"))
    assert not d.allowed
    assert d.status is ScopeStatus.MISSING
    assert "MISSING" in d.explanation


def test_ambiguous_scope_blocks_and_explains():
    # Authorization present but no targets -> ambiguous pause state.
    engine = PolicyEngine(make_scope(in_scope=[]))
    d = engine.evaluate(req(target="https://example.com/"))
    assert not d.allowed
    assert d.status is ScopeStatus.AMBIGUOUS


def test_out_of_scope_url_blocked_before_network():
    engine = PolicyEngine(make_scope())
    d = engine.evaluate(req(target="https://mail.example.com/", method="GET"))
    assert not d.allowed
    assert "target_out_of_scope" in d.violations


def test_unlisted_target_blocked():
    engine = PolicyEngine(make_scope())
    d = engine.evaluate(req(target="https://not-in-scope.org/", method="GET"))
    assert not d.allowed


def test_in_scope_get_allowed():
    engine = PolicyEngine(make_scope())
    d = engine.evaluate(req(target="https://example.com/", method="GET"))
    assert d.allowed, d.explanation


def test_disallowed_method_blocked():
    engine = PolicyEngine(make_scope())
    d = engine.evaluate(req(target="https://example.com/", method="DELETE"))
    assert not d.allowed
    assert any(v.startswith("method_denied:") for v in d.violations)


def test_active_testing_requires_flag():
    engine = PolicyEngine(make_scope(active_testing_enabled=False))
    d = engine.evaluate(
        req(target="https://example.com/", method="POST", test_class="vulnerability_scanning")
    )
    assert not d.allowed
    assert "active_testing_disabled" in d.violations


def test_active_testing_requires_allowed_class():
    engine = PolicyEngine(make_scope(allowed_test_classes=set()))
    d = engine.evaluate(req(target="https://example.com/", method="POST", test_class="fuzzing"))
    assert not d.allowed


def test_hard_prohibited_action_cannot_be_enabled():
    # Even if a campaign tries to allow DoS via prohibited_actions being
    # overridden, HARD_PROHIBITED_ACTIONS always applies.
    scope = make_scope(prohibited_actions={"denial_of_service"})
    engine = PolicyEngine(scope)
    d = engine.evaluate(req(action="denial_of_service", target="https://example.com/"))
    assert not d.allowed


def test_shell_disabled_by_default():
    engine = PolicyEngine(make_scope())
    d = engine.evaluate(req(tool="shell", shell_command=["nmap", "-sV"]))
    assert not d.allowed
    assert "shell_not_approved" in d.violations


def test_shell_allowed_when_test_class_granted():
    engine = PolicyEngine(make_scope(allowed_test_classes={"shell"}))
    assert engine.evaluate(req(tool="shell", shell_command=["ls"])).allowed


def test_block_produces_event_with_id():
    engine = PolicyEngine(make_scope())
    d = engine.evaluate(req(target="https://blocked.example/", method="GET"))
    assert d.blocked_event_id
    events = engine.blocked_events()
    assert d.blocked_event_id in events
    assert "target_unlisted" in events[d.blocked_event_id].violations


def test_reconnaissance_without_testing_flag_still_ok():
    # Read-only recon on an allowed target needs no active-testing flag.
    engine = PolicyEngine(make_scope(active_testing_enabled=False))
    assert engine.evaluate(req(target="https://example.com/", method="GET")).allowed
