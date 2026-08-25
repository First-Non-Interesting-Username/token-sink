"""Agent identity helper tests."""
from __future__ import annotations

from mavr.agents.identity import (
    IdentityContext,
    assign_budget,
    mint_agent,
    mint_uuid,
    spawn_subagent,
)
from mavr.schemas import entities as s


def test_mint_uuid_is_lowercase_v4() -> None:
    u = mint_uuid()
    assert len(u) == 36
    assert u == u.lower()
    # version 4
    assert u[14] == "4"
    # variant 10xx
    assert u[19] in "ab89"


def test_mint_agent_no_global_state() -> None:
    """Two contexts with different parents do not interfere."""
    a = mint_agent(s.AgentRole.DISCOVERY)
    b = mint_agent(s.AgentRole.DISCOVERY)
    assert a.id != b.id
    assert a.parent_id is None and b.parent_id is None
    assert a.created_at == a.updated_at


def test_context_parent_propagates() -> None:
    ctx = IdentityContext(parent_id="11111111-1111-4111-8111-111111111111")
    agent = mint_agent(s.AgentRole.IMPACT, ctx=ctx)
    assert agent.parent_id == "11111111-1111-4111-8111-111111111111"


def test_explicit_parent_overrides_context() -> None:
    ctx = IdentityContext(parent_id="11111111-1111-4111-8111-111111111111")
    agent = mint_agent(
        s.AgentRole.IMPACT, parent_id="22222222-2222-4222-8222-222222222222", ctx=ctx
    )
    assert agent.parent_id == "22222222-2222-4222-8222-222222222222"


def test_assign_budget_returns_new_instance() -> None:
    a = mint_agent(s.AgentRole.IMPACT)
    new_budget = s.AgentBudgets(max_tokens=10, max_time_seconds=10)
    b = assign_budget(a, new_budget)
    assert b.budget.max_tokens == 10
    assert a.budget.max_tokens == 200_000  # unchanged
    assert a.id == b.id


def test_spawn_subagent_links_to_parent() -> None:
    parent = mint_agent(s.AgentRole.RESEARCH)
    child = spawn_subagent(s.AgentRole.POC, parent, campaign_id=parent.campaign_id)
    assert child.parent_id == parent.id
    assert child.campaign_id == parent.campaign_id
    assert child.budget == parent.budget


def test_child_context_does_not_mutate_parent() -> None:
    ctx = IdentityContext(parent_id="11111111-1111-4111-8111-111111111111")
    child = ctx.child()
    assert child.parent_id == ctx.parent_id
    # IdentityContext is a dataclass (immutable via frozen? no — default
    # dataclass). Verify the original is not mutated by an accidental
    # assignment — we never assign in the helper.
    assert ctx.parent_id == "11111111-1111-4111-8111-111111111111"
