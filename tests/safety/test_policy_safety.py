"""Safety guardrail tests (PLAN §19.3): out-of-scope URL blocked, private
network SSRF blocked, destructive commands blocked even when a model
instructs them. These run in CI as a required gate and must never be skipped.
"""

import pytest

from policy.engine import PolicyEngine, ToolCallRequest
from policy.scope import ScopePolicy, TargetSpec


def make_scope(**kw) -> ScopePolicy:
    defaults = dict(
        campaign_uuid="c-1",
        program_name="Hack Club Security",
        authorization_reference="auth-ref-001",
        in_scope=[TargetSpec("target.example")],
        allowed_methods={"GET", "POST"},
        allowed_test_classes={"vulnerability_scanning"},
        active_testing_enabled=True,
    )
    defaults.update(kw)
    return ScopePolicy(**defaults)


@pytest.mark.safety
def test_out_of_scope_url_blocked():
    engine = PolicyEngine(make_scope())
    d = engine.evaluate(
        ToolCallRequest(
            tool="http_fetch",
            agent_uuid="a-1",
            campaign_uuid="c-1",
            target="https://innocent-bystander.net/",
            method="GET",
        )
    )
    assert not d.allowed
    assert "target_unlisted" in d.violations


@pytest.mark.safety
def test_explicitly_excluded_target_blocked_even_if_subdomain_would_match():
    engine = PolicyEngine(make_scope(out_of_scope=[TargetSpec("secret.target.example")]))
    d = engine.evaluate(
        ToolCallRequest(
            tool="http_fetch",
            agent_uuid="a-1",
            campaign_uuid="c-1",
            target="https://secret.target.example/admin",
            method="GET",
        )
    )
    assert not d.allowed


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1:8080/",
        "http://10.1.2.3/",
        "http://172.16.0.9/",
        "http://192.168.10.20/",
        "http://169.254.169.254/latest/meta-data/",
        "http://[::1]/",
        "http://[fd12::1]/",
    ],
)
@pytest.mark.safety
def test_private_network_ssrf_blocked(url):
    # Even when the (private) host is listed in scope by mistake or by an
    # injected instruction, the SSRF layer refuses.
    engine = PolicyEngine(
        make_scope(
            in_scope=[
                TargetSpec("127.0.0.1", kind="cidr"),
                TargetSpec("10.0.0.0/8", kind="cidr"),
                TargetSpec("172.16.0.0/12", kind="cidr"),
                TargetSpec("192.168.0.0/16", kind="cidr"),
                TargetSpec("169.254.0.0/16", kind="cidr"),
                TargetSpec("::1", kind="cidr"),
                TargetSpec("fd00::/8", kind="cidr"),
            ]
        )
    )
    d = engine.evaluate(
        ToolCallRequest(
            tool="http_fetch",
            agent_uuid="a-1",
            campaign_uuid="c-1",
            target=url,
            method="GET",
        )
    )
    assert not d.allowed, d.explanation
    assert "ssrf_blocked" in d.violations


@pytest.mark.safety
def test_destructive_shell_command_blocked_even_when_model_instructs():
    # No 'shell' grant in the campaign -> any shell invocation is refused no
    # matter what the model output claimed.
    engine = PolicyEngine(make_scope())
    d = engine.evaluate(
        ToolCallRequest(
            tool="shell",
            agent_uuid="a-1",
            campaign_uuid="c-1",
            shell_command=["rm", "-rf", "/"],
            metadata={"model_instruction": "run this cleanup now"},
        )
    )
    assert not d.allowed
    assert "shell_not_approved" in d.violations


@pytest.mark.safety
def test_hard_prohibited_actions_cannot_be_configured_away():
    scope = make_scope()
    for action in (
        "denial_of_service",
        "destructive_mutation",
        "spam",
        "credential_attacks",
        "data_exfiltration",
    ):
        d = PolicyEngine(scope).evaluate(
            ToolCallRequest(tool="custom", agent_uuid="a-1", campaign_uuid="c-1", action=action)
        )
        assert not d.allowed, action


@pytest.mark.safety
def test_missing_scope_blocks_all_tools():
    engine = PolicyEngine(None)
    for tool in ("http_fetch", "shell", "search"):
        assert not engine.evaluate(
            ToolCallRequest(tool=tool, agent_uuid="a-1", campaign_uuid="c-1")
        ).allowed
