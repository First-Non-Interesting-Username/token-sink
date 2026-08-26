"""Subagent spawning protocol (spec §6 Subagents).

This module layers the *protocol* rules on top of the mechanical
spawn in :func:`mavr.orchestrator.runtime.spawn_subagent`:

* **Request schema** — a validated :class:`SubagentSpec` (pydantic,
  extra-forbid) that every spawn request must satisfy before a child
  is minted. The runtime's ``SubagentRequest`` dataclass stays the
  transport shape; this adds strict validation + inheritance.
* **Budget/timeout inheritance** — the child budget is clamped to be
  component-wise ≤ the parent's, and the timeout is bounded by the
  parent budget's ``max_time_seconds``. A parent can never grant a
  subagent more resources than it holds itself.
* **Output citation rules** — when a parent summarizes subagent
  outputs it must cite them. :func:`summarize_subagent_outputs`
  rejects any claim whose cited ids do not correspond to actual
  spawned children of the parent, so unverified/unrelated outputs
  cannot be presented as fact.

Pure functions only — no global mutable state.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from mavr.orchestrator.runtime import SubagentRequest
from mavr.schemas import entities as schema

# ---- request schema -------------------------------------------------------


class SubagentSpec(BaseModel):
    """Validated spawn request.

    Mirrors :class:`~mavr.orchestrator.runtime.SubagentRequest` but with
    strict validation: non-empty objective, non-negative timeout, and
    completion criteria required for active-testing requests.
    """

    model_config = ConfigDict(extra="forbid")

    objective: str = Field(min_length=1)
    role: schema.AgentRole = schema.AgentRole.SUBAGENT
    allowed_tools: tuple[str, ...] = ()
    scope: dict[str, Any] = Field(default_factory=dict)
    budget: schema.AgentBudgets | None = None
    timeout_seconds: int = Field(default=600, ge=0)
    active_testing_allowed: bool = False
    completion_criteria: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("objective")
    @classmethod
    def _objective_not_blank(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("objective must not be blank")
        return v

    @field_validator("allowed_tools")
    @classmethod
    def _tools_non_blank(cls, v: tuple[str, ...]) -> tuple[str, ...]:
        if any(not t.strip() for t in v):
            raise ValueError("allowed_tools entries must be non-blank")
        return v


def validate_request(
    request: SubagentRequest, *, parent: schema.Agent
) -> SubagentRequest:
    """Validate a spawn request against the protocol and the parent agent.

    Returns the (possibly adjusted) request on success; raises
    :class:`SpawnProtocolError` on violation.
    """
    try:
        spec = SubagentSpec(
            objective=request.objective,
            role=request.role,
            allowed_tools=tuple(request.allowed_tools),
            scope=dict(request.scope),
            budget=request.budget,
            timeout_seconds=request.timeout_seconds,
            active_testing_allowed=request.active_testing_allowed,
            completion_criteria=request.completion_criteria,
            metadata=dict(request.metadata),
        )
    except Exception as exc:
        raise SpawnProtocolError(f"invalid subagent request: {exc}") from exc
    if spec.active_testing_allowed and not spec.completion_criteria.strip():
        # Active testing is dangerous enough that the parent must state
        # exactly when the subagent may stop.
        raise SpawnProtocolError(
            "active-testing subagent requires explicit completion_criteria"
        )
    if parent.campaign_id is None:
        raise SpawnProtocolError(
            "parent agent has no campaign_id — cannot scope a subagent"
        )
    return _inherit(request, parent=parent)


class SpawnProtocolError(ValueError):
    """A spawn request violates the §6 subagent protocol."""


# ---- budget / timeout inheritance -----------------------------------------


def clamp_budget(
    child: schema.AgentBudgets, parent: schema.AgentBudgets
) -> schema.AgentBudgets:
    """Clamp a child budget component-wise to the parent's."""
    return schema.AgentBudgets(
        max_tokens=min(child.max_tokens, parent.max_tokens),
        max_time_seconds=min(child.max_time_seconds, parent.max_time_seconds),
        max_tool_calls=min(child.max_tool_calls, parent.max_tool_calls),
        max_network_requests=min(
            child.max_network_requests, parent.max_network_requests
        ),
    )


def inherit_budget(
    requested: schema.AgentBudgets | None, parent: schema.AgentBudgets
) -> schema.AgentBudgets:
    """Resolve the child budget: requested-but-clamped, or the parent's."""
    return clamp_budget(requested or parent, parent)


def inherit_timeout(
    requested_seconds: int, parent: schema.AgentBudgets
) -> int:
    """Bound the child timeout by the parent's time budget."""
    return min(max(int(requested_seconds), 0), parent.max_time_seconds)


def _inherit(
    request: SubagentRequest, *, parent: schema.Agent
) -> SubagentRequest:
    """Return a copy of ``request`` with inherited budget and timeout."""
    budget = inherit_budget(request.budget, parent.budget)
    timeout = inherit_timeout(request.timeout_seconds, parent.budget)
    if budget == request.budget and timeout == request.timeout_seconds:
        return request
    return SubagentRequest(
        objective=request.objective,
        role=request.role,
        output_schema=request.output_schema,
        allowed_tools=tuple(request.allowed_tools),
        scope=dict(request.scope),
        budget=budget,
        timeout_seconds=timeout,
        active_testing_allowed=request.active_testing_allowed,
        completion_criteria=request.completion_criteria,
        metadata=dict(request.metadata),
    )


# ---- output citation rules -------------------------------------------------


@dataclass(frozen=True)
class SubagentOutput:
    """One subagent result available for citation."""

    agent_id: str
    task_id: str


@dataclass(frozen=True)
class CitationRuleViolation(ValueError):
    """Raised as a value; use ``str()`` for the message."""


def summarize_subagent_outputs(
    *,
    parent: schema.Agent,
    outputs: dict[str, SubagentOutput],
    claims: list[tuple[str, tuple[str, ...]]],
) -> str:
    """Assemble a parent summary that cites its subagent outputs.

    ``outputs`` maps an output key to the actual spawned subagent
    (agent id + its task id). ``claims`` is a list of
    ``(claim_text, cited_keys)`` pairs — each claim must cite at least
    one key present in ``outputs``.

    Per §6, the parent "must summarize and cite subagent outputs rather
    than treating them as unquestioned truth": a claim citing nothing,
    or citing an unknown/output-less key, raises
    :class:`SpawnProtocolError`. The returned string prefixes every
    claim with its citations in ``[cite:<key>]`` form.
    """
    lines: list[str] = []
    for text, keys in claims:
        if not keys:
            raise SpawnProtocolError(
                f"claim without any subagent citation: {text!r}"
            )
        unknown = [k for k in keys if k not in outputs]
        if unknown:
            raise SpawnProtocolError(
                f"claim cites unknown subagent output(s) {unknown}: {text!r}"
            )
        cites = " ".join(f"[cite:{k}]" for k in keys)
        lines.append(f"{cites} {text}")
    header = f"Summary by agent {parent.id} of {len(outputs)} subagent output(s):"
    return "\n".join([header, *lines]) if lines else header
