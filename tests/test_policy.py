"""Scope policy engine + SSRF denylist tests."""
from __future__ import annotations

import pytest

from mavr.policy.engine import (
    ActionClass,
    DecisionKind,
    ScopePolicyEngine,
    ToolCall,
    evaluate_url,
)
from mavr.schemas import entities as schema


def _campaign(scope: schema.ScopePolicy | None = None) -> schema.Campaign:
    return schema.Campaign(
        id="11111111-1111-4111-8111-111111111111",
        name="test",
        target_spec={"hosts": ["example.com"]},
    )


def _scope(**over) -> schema.ScopePolicy:
    base = dict(
        id="22222222-2222-4222-8222-222222222222",
        campaign_id="11111111-1111-4111-8111-111111111111",
        allowed_targets=["example.com", "*.example.org"],
        allowed_methods=["GET", "HEAD"],
        action_allowlist=[],
    )
    base.update(over)
    return schema.ScopePolicy(**base)


def test_allow_basic_get() -> None:
    engine = ScopePolicyEngine(resolve_dns=False)
    c = _campaign()
    s = _scope()
    d = engine.evaluate(
        c, s, ToolCall(url="https://example.com/foo", method="GET")
    )
    assert d.kind == DecisionKind.ALLOW


def test_method_not_in_allowlist_denied() -> None:
    engine = ScopePolicyEngine(resolve_dns=False)
    d = engine.evaluate(
        _campaign(),
        _scope(),
        ToolCall(url="https://example.com/", method="POST"),
    )
    assert d.kind == DecisionKind.DENY
    assert d.rule == "method_not_allowed"


def test_host_not_in_scope_denied() -> None:
    engine = ScopePolicyEngine(resolve_dns=False)
    d = engine.evaluate(
        _campaign(),
        _scope(),
        ToolCall(url="https://evil.com/", method="GET"),
    )
    assert d.kind == DecisionKind.DENY
    assert d.rule == "host_not_in_scope"


def test_wildcard_subdomain_match() -> None:
    engine = ScopePolicyEngine(resolve_dns=False)
    d = engine.evaluate(
        _campaign(),
        _scope(),
        ToolCall(url="https://api.example.org/", method="GET"),
    )
    assert d.kind == DecisionKind.ALLOW


def test_dos_action_class_always_denied() -> None:
    engine = ScopePolicyEngine(resolve_dns=False)
    d = engine.evaluate(
        _campaign(),
        _scope(),
        ToolCall(
            url="https://example.com/",
            action_class=ActionClass.DENIAL_OF_SERVICE.value,
        ),
    )
    assert d.kind == DecisionKind.DENY
    assert d.rule == "forbidden_action_class"


def test_exfiltration_action_class_always_denied() -> None:
    engine = ScopePolicyEngine(resolve_dns=False)
    d = engine.evaluate(
        _campaign(),
        _scope(),
        ToolCall(
            url="https://example.com/",
            action_class=ActionClass.EXFILTRATION.value,
        ),
    )
    assert d.kind == DecisionKind.DENY


def test_active_testing_requires_human_approval() -> None:
    engine = ScopePolicyEngine(resolve_dns=False)
    d = engine.evaluate(
        _campaign(),
        _scope(),  # human_approved=False
        ToolCall(url="https://example.com/", action_class=ActionClass.ACTIVE_TEST.value),
    )
    assert d.kind == DecisionKind.QUARANTINE
    assert d.rule == "active_testing_unapproved"


def test_active_testing_with_approval_allowed() -> None:
    engine = ScopePolicyEngine(resolve_dns=False)
    d = engine.evaluate(
        _campaign(),
        _scope(human_approved=True, active_testing=True),
        ToolCall(url="https://example.com/", action_class=ActionClass.ACTIVE_TEST.value),
    )
    assert d.kind == DecisionKind.ALLOW


# ---- SSRF denylist ------------------------------------------------------


@pytest.mark.parametrize(
    "ip",
    [
        "127.0.0.1",
        "127.5.5.5",
        "10.1.2.3",
        "172.16.0.1",
        "192.168.1.1",
        "169.254.1.1",        # link-local
        "169.254.169.254",    # cloud metadata
        "224.0.0.1",          # multicast
        "0.0.0.0",
        "100.64.0.1",         # CGNAT
        "::1",
        "fc00::1",
        "fe80::1",
    ],
)
def test_private_ip_blocked(ip: str) -> None:
    engine = ScopePolicyEngine(resolve_dns=False)
    d = engine.evaluate(
        _campaign(),
        _scope(),
        ToolCall(
            url="https://example.com/",
            method="GET",
            resolved_ips=(ip,),
        ),
    )
    assert d.kind == DecisionKind.DENY
    assert d.rule == "ssrf_denylist"


def test_public_ip_allowed() -> None:
    engine = ScopePolicyEngine(resolve_dns=False)
    d = engine.evaluate(
        _campaign(),
        _scope(),
        ToolCall(
            url="https://example.com/",
            method="GET",
            resolved_ips=("93.184.216.34",),
        ),
    )
    assert d.kind == DecisionKind.ALLOW


def test_explicit_unsafe_networking_overrides_denylist() -> None:
    engine = ScopePolicyEngine(resolve_dns=False)
    d = engine.evaluate(
        _campaign(),
        _scope(
            explicit_unsafe_networking=True,
            human_approved=True,
            allowed_targets=["127.0.0.1"],
        ),
        ToolCall(
            url="http://127.0.0.1:8080/admin",
            method="GET",
            resolved_ips=("127.0.0.1",),
        ),
    )
    assert d.kind == DecisionKind.ALLOW


def test_unsafe_networking_without_human_approval_still_blocked() -> None:
    engine = ScopePolicyEngine(resolve_dns=False)
    d = engine.evaluate(
        _campaign(),
        _scope(explicit_unsafe_networking=True, human_approved=False),
        ToolCall(
            url="http://127.0.0.1:8080/admin",
            method="GET",
            resolved_ips=("127.0.0.1",),
        ),
    )
    assert d.kind == DecisionKind.DENY


# ---- other --------------------------------------------------------------


def test_bad_scheme_denied() -> None:
    engine = ScopePolicyEngine(resolve_dns=False)
    d = engine.evaluate(
        _campaign(),
        _scope(),
        ToolCall(url="ftp://example.com/", method="GET"),
    )
    assert d.kind == DecisionKind.DENY
    assert d.rule == "bad_scheme"


def test_rate_limit_triggers_quarantine() -> None:
    from mavr.policy.engine import RateCounter

    engine = ScopePolicyEngine(resolve_dns=False)
    d = engine.evaluate(
        _campaign(),
        _scope(rate_limit_per_minute=10),
        ToolCall(url="https://example.com/"),
        rate=RateCounter(per_minute=11),
    )
    assert d.kind == DecisionKind.QUARANTINE
    assert d.rule == "rate_limit_exceeded"


def test_evaluate_url_helper(tmp_dir) -> None:  # noqa: ANN001
    engine = ScopePolicyEngine(resolve_dns=False)
    d = evaluate_url(
        engine,
        _campaign(),
        _scope(),
        "https://example.com/x",
    )
    assert d.kind == DecisionKind.ALLOW
