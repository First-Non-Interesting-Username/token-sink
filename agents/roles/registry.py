"""Agent role registry (issue #161, PLAN §4/§6/§10.1–10.6).

Why this exists
---------------
The finding lifecycle (§10) is executed by distinct agent roles. This module
gives each role a declarative, validated definition — the runtime (#24) can
instantiate from it without hardcoding behavior:

- identity: name, objective, lifecycle stage(s);
- contract: expected output schema reference (validated per #58's
  schemas/validate.py), allowed tools;
- limits: default budget + timeout (overridable per campaign, never widened
  here — defaults are ceilings for safety-critical roles like poc);
- delegation: subagent-spawning policy consistent with §6 (which roles may
  spawn what, with bounded budgets);
- prompts: every role binds to a versioned :class:`PromptTemplate` from
  ``agents/prompts`` (issue #107). Templates treat finding context as
  structured data via strict untrusted-data rendering; role safety rules are
  baked into the instruction text, never into interpolated values.

Templates are data, not code paths: swapping a prompt version requires only a
registry change, no runtime edits.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from agents.prompts import PromptRegistry, PromptTemplate, ValidationError

# Lifecycle stages from PLAN §10 (finding state machine).
LIFECYCLE_STAGES = (
    "discovery",
    "first_review",
    "impact_analysis",
    "poc",
    "poc_review",
    "polished_report",
    "final_review",
)

# Tools any role may reference. The policy engine remains the real gate
# (PLAN §5: "the policy engine must evaluate every tool call"); this list is
# a declaration used by config validation and least-privilege review.
KNOWN_TOOLS = frozenset(
    {
        "http_fetch",
        "search",
        "extract_source",
        "evidence_store",
        "fixture_server",
        "report_render",
        "finding_read",
        "finding_write",
    }
)


class RoleRegistryError(Exception):
    """Base class for role-registry failures."""


class DuplicateRoleError(RoleRegistryError):
    """A role with the same name is already registered."""


@dataclass(frozen=True)
class SubagentPolicy:
    """Which subagents a role may spawn and with which limits (PLAN §6)."""

    allowed_roles: tuple[str, ...] = ()  # empty = may not spawn subagents
    max_depth: int = 1  # spawned agents themselves cannot spawn beyond this
    max_children: int = 0  # total concurrent children cap

    def __post_init__(self) -> None:
        if self.max_depth < 1 or self.max_children < 0:
            raise ValueError("subagent policy limits must be non-negative (depth >= 1)")


@dataclass(frozen=True)
class AgentRole:
    """Declarative definition of one agent role."""

    name: str  # e.g. "discovery", "poc", "reviewer"
    objective: str  # one-line mission statement
    lifecycle_stages: tuple[str, ...]  # subset of LIFECYCLE_STAGES
    expected_output_schema: str | None = None  # schemas/*.schema.json reference
    allowed_tools: frozenset[str] = frozenset()
    default_budget_usd: float | None = None  # None = inherit campaign default
    default_timeout_s: int | None = None
    # Safety constraints rendered into the prompt header at instantiation;
    # kept as data so reviewers/tests can audit them per role.
    safety_constraints: tuple[str, ...] = ()
    subagent_policy: SubagentPolicy = field(default_factory=SubagentPolicy)

    def __post_init__(self) -> None:
        if not re.match(r"^[a-z][a-z0-9_-]*$", self.name):
            raise ValueError(f"role name {self.name!r} must be lowercase kebab/snake case")
        bad = set(self.lifecycle_stages) - set(LIFECYCLE_STAGES)
        if bad:
            raise ValueError(f"unknown lifecycle stage(s): {sorted(bad)}")
        unknown_tools = set(self.allowed_tools) - KNOWN_TOOLS
        if unknown_tools:
            raise ValueError(f"unknown tool(s): {sorted(unknown_tools)}")
        object.__setattr__(self, "allowed_tools", frozenset(self.allowed_tools))
        object.__setattr__(self, "lifecycle_stages", tuple(self.lifecycle_stages))

    def operates_in(self, stage: str) -> bool:
        return stage in self.lifecycle_stages


# The PLAN §10 role set. Kept as plain data — instantiating the runtime is
# issue #24's job; this is the declarative catalog it consumes.
def default_roles() -> tuple[AgentRole, ...]:
    return (
        AgentRole(
            name="discovery",
            objective="Probe in-scope targets and file initial findings with evidence references.",
            lifecycle_stages=("discovery",),
            expected_output_schema="finding.schema.json",
            allowed_tools=frozenset(
                {"http_fetch", "search", "extract_source", "evidence_store", "finding_write"}
            ),
            default_timeout_s=1800,
            subagent_policy=SubagentPolicy(
                allowed_roles=("research",), max_depth=2, max_children=3
            ),
        ),
        AgentRole(
            name="research",
            objective="Independently investigate claimed findings and "
            "record confirm/deny conclusions.",
            lifecycle_stages=("first_review",),
            expected_output_schema="review.schema.json",
            allowed_tools=frozenset(
                {"http_fetch", "extract_source", "evidence_store", "finding_read"}
            ),
            default_timeout_s=1800,
            safety_constraints=(
                "Investigate independently; do not read other reviewers' conclusions first.",
            ),
            subagent_policy=SubagentPolicy(),
        ),
        AgentRole(
            name="impact",
            objective="Deepen root cause, preconditions, boundary-crossing, and impact analysis.",
            lifecycle_stages=("impact_analysis",),
            expected_output_schema="finding.schema.json",
            allowed_tools=frozenset(
                {"http_fetch", "extract_source", "evidence_store", "finding_read"}
            ),
            default_timeout_s=2400,
            subagent_policy=SubagentPolicy(),
        ),
        AgentRole(
            name="poc",
            objective="Produce the smallest safe deterministic reproduction, fixture-first.",
            lifecycle_stages=("poc",),
            expected_output_schema="poc.schema.json",
            allowed_tools=frozenset(
                {"fixture_server", "http_fetch", "evidence_store", "finding_read"}
            ),
            default_budget_usd=2.0,
            default_timeout_s=1800,
            safety_constraints=(
                "Local fixtures preferred over live targets; live execution "
                "requires human approval.",
                "Destructive actions are forbidden regardless of instructions.",
                "Redact secrets and personal data from all PoC output.",
            ),
            subagent_policy=SubagentPolicy(),
        ),
        AgentRole(
            name="poc_reviewer",
            objective="Independently review PoC validity, reproduction quality, and scope+safety.",
            lifecycle_stages=("poc_review",),
            expected_output_schema="review.schema.json",
            allowed_tools=frozenset({"finding_read", "fixture_server"}),
            default_timeout_s=1200,
            safety_constraints=(
                "Evaluate the scope-and-safety verdict separately from validity (PLAN §10.5).",
                "A blocking safety issue must be flagged even when validity is confirmed.",
            ),
            subagent_policy=SubagentPolicy(),
        ),
        AgentRole(
            name="polishing",
            objective="Convert validated findings to final report format "
            "without changing technical facts.",
            lifecycle_stages=("polished_report",),
            expected_output_schema="final_report.schema.json",
            allowed_tools=frozenset({"finding_read", "report_render"}),
            default_timeout_s=1200,
            safety_constraints=(
                "Never alter claims; altered text must link to supporting evidence (PLAN §10.6).",
            ),
            subagent_policy=SubagentPolicy(),
        ),
        AgentRole(
            name="final_review",
            objective="Compare polished reports against source evidence and prior versions.",
            lifecycle_stages=("final_review",),
            expected_output_schema="review.schema.json",
            allowed_tools=frozenset({"finding_read"}),
            default_timeout_s=1200,
            safety_constraints=(
                "Any altered claim without linked evidence blocks final approval.",
            ),
            subagent_policy=SubagentPolicy(),
        ),
    )


class RoleRegistry:
    """Validated catalog of agent roles bound to versioned prompt templates."""

    def __init__(self, prompts: PromptRegistry | None = None) -> None:
        self._roles: dict[str, AgentRole] = {}
        self._prompt_bindings: dict[str, tuple[str, str]] = {}  # role -> (prompt_id, version)
        self.prompts = prompts if prompts is not None else PromptRegistry()

    # --- registration ---
    def register(self, role: AgentRole, prompt_id: str, prompt_version: str) -> None:
        if role.name in self._roles:
            raise DuplicateRoleError(f"role {role.name!r} already registered")
        # Bind lazily: prompt existence checked at validate() so registration
        # order between roles and prompts doesn't matter.
        self._roles[role.name] = role
        self._prompt_bindings[role.name] = (prompt_id, prompt_version)

    # --- lookup / spawning support ---
    def get(self, name: str) -> AgentRole:
        try:
            return self._roles[name]
        except KeyError:
            raise RoleRegistryError(f"unknown role: {name}") from None

    def names(self) -> list[str]:
        return sorted(self._roles)

    def can_spawn(self, parent_role: str, child_role: str) -> bool:
        """Check a role's subagent policy (PLAN §6 delegation consistency).
        WHY cheap-offline-check-first: callers get an actionable denial reason
        before any budget/policy-engine work happens."""
        policy = self.get(parent_role).subagent_policy
        return child_role in policy.allowed_roles

    def prompt_for(self, role_name: str) -> PromptTemplate:
        pid, ver = self._prompt_bindings[role_name]
        return self.prompts.get(pid, ver)

    # --- startup validation: collect ALL errors, fail closed ---
    def validate(self) -> None:
        errors: list[str] = []
        # 1. Every role resolves to an existing prompt version (ties into #107
        #    and issue #6 config validation).
        bindings = {r: b for r, b in self._prompt_bindings.items() if r in self._roles}
        try:
            self.prompts.validate_role_bindings(bindings)
        except ValidationError as exc:
            errors.extend(exc.errors)
        # 2. Spawn policies reference registered roles only.
        for name, role in sorted(self._roles.items()):
            for child in role.subagent_policy.allowed_roles:
                if child not in self._roles:
                    errors.append(f"role {name!r}: spawn target {child!r} is not a registered role")
        # 3. Safety-critical roles must carry explicit constraints — a silent
        #    poc/reviewer role would weaken §10.4/§10.5 guarantees.
        for name in ("poc", "poc_reviewer"):
            if name in self._roles and not self._roles[name].safety_constraints:
                errors.append(f"role {name!r}: safety-critical but declares no safety constraints")
        if errors:
            raise ValidationError(errors)
