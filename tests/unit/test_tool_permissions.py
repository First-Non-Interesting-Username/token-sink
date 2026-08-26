"""Tests for the tool-permission registry & enforcement layer (issue #173).

Covers the issue's required scenarios: unregistered-tool block,
subagent-cannot-escalate, shell-disabled-by-default, env-secret stripping,
and egress routed through the scope filter.
"""

from __future__ import annotations

import pytest

from policy.tool_permissions import (
    SEARCH,
    SHELL,
    SUBAGENT_SPAWN,
    EgressClass,
    ToolDescriptor,
    ToolGrant,
    ToolPermissionRegistry,
    build_sandbox_env,
    check_permission,
    sanitize_env,
)


def make_registry(*extra: ToolDescriptor) -> ToolPermissionRegistry:
    return ToolPermissionRegistry(list(extra) if extra else None)


def test_unregistered_tool_is_blocked():
    reg = make_registry()
    decision = check_permission(
        "does-not-exist",
        reg,
        grants={},
        agent_uuid="a1",
        shell_enabled_in_policy=False,
        active_testing_allowed=False,
    )
    assert not decision.allowed
    assert decision.violation == "tool_unregistered"


def test_registered_tool_without_grant_is_blocked():
    reg = make_registry()
    d = check_permission(
        "search",
        reg,
        grants={},
        agent_uuid="a1",
        shell_enabled_in_policy=False,
        active_testing_allowed=False,
        # Even with a filter callable, no grant means no run.
        scope_filter_check=type("V", (), {"allowed": True, "reason": ""})(),
    )
    assert not d.allowed and d.violation == "grant_missing"


def test_grant_mismatch_is_blocked():
    reg = make_registry()
    grants = {"a1": ToolGrant("search", "a1")}
    d = check_permission(
        "fetch",
        reg,
        grants,
        "a1",
        False,
        False,
        scope_filter_check=type("V", (), {"allowed": True, "reason": ""})(),
    )
    assert not d.allowed and d.violation == "grant_mismatch"


def test_subagent_cannot_escalate():
    """A grant whose parent has none must fail structurally (§6)."""
    reg = make_registry(SHELL)
    # Child granted shell; parent has NO grant record -> escalation blocked.
    grants = {"child": ToolGrant("shell", "child", parent_uuid="parent", allow_shell=True)}
    d = check_permission(
        "shell",
        reg,
        grants,
        "child",
        shell_enabled_in_policy=True,
        active_testing_allowed=True,
    )
    assert not d.allowed
    assert d.violation == "subagent_escalation_blocked"


def test_subagent_subset_of_parent_succeeds():
    reg = make_registry()
    grants = {
        "parent": ToolGrant("search", "parent"),
        # Child's grant mirrors an allowed subset of the parent.
        "child": ToolGrant("search", "child", parent_uuid="parent"),
    }
    d = check_permission(
        "search",
        reg,
        grants,
        "child",
        False,
        False,
        scope_filter_check=type("V", (), {"allowed": True, "reason": ""})(),
    )
    assert d.allowed


def test_shell_disabled_by_default():
    reg = make_registry(SHELL)
    grants = {"a1": ToolGrant("shell", "a1")}
    # Shell is blocked regardless of any grant flag while campaign policy
    # keeps it disabled — dual opt-in means policy alone isn't enough.
    for _ in (False, True):
        d = check_permission(
            "shell",
            reg,
            grants,
            "a1",
            shell_enabled_in_policy=False,  # campaign never enabled it
            active_testing_allowed=True,
        )
        assert not d.allowed
        assert d.violation == "shell_not_approved"


def test_shell_requires_dual_opt_in():
    reg = make_registry(SHELL)
    # Campaign enables shell but agent grant lacks the flag.
    grants = {"a1": ToolGrant("shell", "a1", allow_shell=False)}
    d = check_permission("shell", reg, grants, "a1", True, True)
    assert not d.allowed
    # Both flags set -> allowed.
    grants["a1"] = ToolGrant("shell", "a1", allow_shell=True)
    assert check_permission("shell", reg, grants, "a1", True, True).allowed


def test_active_testing_gate():
    reg = make_registry(SHELL)
    grants = {"a1": ToolGrant("shell", "a1", allow_shell=True)}
    d = check_permission("shell", reg, grants, "a1", True, active_testing_allowed=False)
    assert not d.allowed and d.violation == "active_testing_disabled"


class _Verdict:
    def __init__(self, allowed: bool, reason: str = ""):
        self.allowed = allowed
        self.reason = reason


def test_egress_routed_through_scope_filter():
    reg = make_registry()  # search/fetch are ALLOWLIST_ONLY

    # No filter callable provided -> direct-socket bypass is refused even
    # with a valid grant.
    grants = {"a1": ToolGrant("search", "a1")}
    d = check_permission("search", reg, grants, "a1", False, False)
    assert not d.allowed and d.violation == "egress_bypass_blocked"

    # Filter denies out-of-scope destination.
    d = check_permission(
        "search",
        reg,
        grants,
        "a1",
        False,
        False,
        scope_filter_check=_Verdict(False, "target unlisted"),
    )
    assert not d.allowed
    assert d.violation == "egress_scope_denied"
    assert "unlisted" in d.reason

    # In-scope destination passes.
    d = check_permission(
        "search",
        reg,
        grants,
        "a1",
        False,
        False,
        scope_filter_check=_Verdict(True),
    )
    assert d.allowed


def test_none_egress_needs_no_filter():
    reg = make_registry()
    grants = {"a1": ToolGrant("subagent-spawn", "a1")}
    assert check_permission("subagent-spawn", reg, grants, "a1", False, False).allowed


def test_shell_env_strips_secrets():
    env = build_sandbox_env(
        {
            "MY_API_KEY": "sk-example-0000000000000000000",
            "GITHUB_TOKEN": "gh-example",
            "DB_PASSWORD": "changeme-not",
            "CUSTOM_SECRET": "x",
        }
    )
    assert sanitize_env(env) == {"PATH": env["PATH"], "HOME": env["HOME"], "LANG": env["LANG"]}


def test_descriptors_declare_honest_capabilities():
    assert SHELL.egress is EgressClass.BROAD
    assert SHELL.destructive_potential and SHELL.active_testing
    assert SEARCH.egress is EgressClass.ALLOWLIST_ONLY
    assert not SUBAGENT_SPAWN.filesystem


def test_invalid_tool_name_rejected():
    with pytest.raises(ValueError):
        ToolDescriptor("", EgressClass.NONE)
    with pytest.raises(ValueError):
        ToolDescriptor("bad name!", EgressClass.NONE)
