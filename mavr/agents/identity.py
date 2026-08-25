"""Agent identity helpers.

No global mutable state — callers pass an :class:`IdentityContext` that
carries the config-driven defaults (budgets) and a parent UUID when
spawning sub-agents.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from mavr.observability.logging import get_logger
from mavr.schemas import entities as schema

log = get_logger(__name__)


def _now() -> datetime:
    return datetime.now(UTC)


def mint_uuid() -> str:
    """Mint a new lowercase UUIDv4 string."""
    return str(uuid4())


@dataclass
class IdentityContext:
    """Context for minting agent identities.

    Holds the default budget and an optional parent UUID. Multiple
    contexts can coexist — there is no module-level mutable state.
    """

    parent_id: str | None = None
    default_budget: schema.AgentBudgets = field(default_factory=schema.AgentBudgets)
    correlation_id: str | None = None

    def child(self) -> IdentityContext:
        """Return a fresh context that defaults new agents' parent to the next
        agent minted by this method, while preserving defaults.
        """
        # We deliberately do NOT pre-allocate an ID for the child; the
        # parent linkage is filled in by ``spawn`` / ``mint``.
        return IdentityContext(
            parent_id=self.parent_id,
            default_budget=self.default_budget,
            correlation_id=self.correlation_id,
        )


def mint_agent(
    role: schema.AgentRole,
    *,
    campaign_id: str | None = None,
    status: schema.AgentStatus = schema.AgentStatus.CREATED,
    budget: schema.AgentBudgets | None = None,
    parent_id: str | None = None,
    ctx: IdentityContext | None = None,
    metadata: dict[str, Any] | None = None,
) -> schema.Agent:
    """Mint a new :class:`schema.Agent` instance with a fresh UUID."""
    parent = parent_id if parent_id is not None else (ctx.parent_id if ctx else None)
    used_budget = budget or (ctx.default_budget if ctx else None) or schema.AgentBudgets()
    now = _now()
    return schema.Agent(
        id=mint_uuid(),
        parent_id=parent,
        role=role,
        status=status,
        campaign_id=campaign_id,
        budget=used_budget,
        metadata=metadata or {},
        created_at=now,
        updated_at=now,
    )


def spawn_subagent(
    role: schema.AgentRole,
    parent: schema.Agent,
    *,
    campaign_id: str | None = None,
    budget: schema.AgentBudgets | None = None,
    metadata: dict[str, Any] | None = None,
) -> schema.Agent:
    """Spawn a subagent linked to a parent agent."""
    return mint_agent(
        role,
        campaign_id=campaign_id or parent.campaign_id,
        status=schema.AgentStatus.QUEUED,
        budget=budget or parent.budget,
        parent_id=parent.id,
        metadata=metadata,
    )


def assign_budget(agent: schema.Agent, budget: schema.AgentBudgets) -> schema.Agent:
    """Return a new agent with the supplied budget (immutable update)."""
    return agent.model_copy(update={"budget": budget, "updated_at": _now()})
