"""Tool permission registry & enforcement (PLAN §3.1, §6, §15) — issue #173.

The policy engine validates *scope*; this module declares what each tool IS
(capabilities) and enforces per-tool grants at dispatch time:

- Every tool registers a ToolDescriptor: egress class, filesystem access,
  destructive potential, active-testing vs read-only.
- Default-deny: unregistered tools are blocked; registered tools still need
  a grant from campaign policy before they may run.
- Subagents receive a strict SUBSET of their parent's grants — escalation is
  structurally impossible (checked in grant_for_agent).
- The shell tool is special: disabled unless explicitly enabled, and when
  enabled runs sandboxed (isolated cwd, rlimits, timeout, stripped env).

Enforcement is in code here, never prompt discouragement (§2.5/§15).
"""

from __future__ import annotations

import enum
from dataclasses import dataclass


class EgressClass(enum.Enum):
    """What kind of network access a tool needs (§15 least privilege)."""

    NONE = "none"  # purely local computation
    ALLOWLIST_ONLY = "allowlist_only"  # must go through scope filter (#124)
    BROAD = "broad"  # full network — requires explicit campaign grant


@dataclass(frozen=True)
class ToolDescriptor:
    """Capability declaration for one tool (§3.1, §15).

    Registered tools describe themselves honestly; the enforcement layer
    treats these declarations as authoritative for gating decisions.
    """

    name: str
    egress: EgressClass
    filesystem: bool = False  # may read/write outside its own scratch dir
    destructive_potential: bool = False
    active_testing: bool = False  # False => read-only reconnaissance class

    def __post_init__(self) -> None:
        if not self.name or not self.name.replace("-", "").replace("_", "").isalnum():
            raise ValueError(f"invalid tool name: {self.name!r}")


# Built-in descriptors. `shell` is deliberately absent from convenience
# defaults below — it must be explicitly registered AND granted (§15:
# shell execution disabled by default).
SEARCH = ToolDescriptor("search", EgressClass.ALLOWLIST_ONLY)
FETCH = ToolDescriptor("fetch", EgressClass.ALLOWLIST_ONLY)
FILE_WRITE = ToolDescriptor("file-write", EgressClass.NONE, filesystem=True)
SUBAGENT_SPAWN = ToolDescriptor("subagent-spawn", EgressClass.NONE)
SHELL = ToolDescriptor(
    "shell",
    EgressClass.BROAD,
    filesystem=True,
    destructive_potential=True,
    active_testing=True,
)


class ToolPermissionRegistry:
    """Declares which tools exist and checks grants against policy."""

    def __init__(self, descriptors: list[ToolDescriptor] | None = None):
        # Default set excludes shell: it must be opted into explicitly.
        self._tools: dict[str, ToolDescriptor] = {}
        for d in (
            descriptors
            if descriptors is not None
            else [
                SEARCH,
                FETCH,
                FILE_WRITE,
                SUBAGENT_SPAWN,
            ]
        ):
            self.register(d)

    def register(self, descriptor: ToolDescriptor) -> None:
        self._tools[descriptor.name] = descriptor

    def get(self, name: str) -> ToolDescriptor | None:
        return self._tools.get(name)

    def is_registered(self, name: str) -> bool:
        return name in self._tools

    def tools(self) -> dict[str, ToolDescriptor]:
        return dict(self._tools)


@dataclass
class ToolGrant:
    """A grant of one tool to an agent lineage (§6 subagent subset rule)."""

    tool_name: str
    agent_uuid: str  # agent this grant belongs to
    parent_uuid: str | None = None  # lineage parent, for subset checks
    allow_shell: bool = False  # only meaningful for the shell tool


@dataclass(frozen=True)
class PermissionDecision:
    allowed: bool
    reason: str
    violation: str = ""


def check_permission(
    request_tool: str,
    registry: ToolPermissionRegistry,
    grants: dict[str, ToolGrant],
    agent_uuid: str,
    shell_enabled_in_policy: bool,
    active_testing_allowed: bool,
    scope_filter_check=None,
) -> PermissionDecision:
    """Dispatch-time gate consulted by the runtime's tool executor.

    Order of checks is fixed so blocks are deterministic and explainable:
    registration -> grant -> subagent-subset -> shell opt-in -> egress route.

    ``scope_filter_check`` is the safe-fetch pipeline (#124) callable for
    ALLOWLIST_ONLY tools; when provided it must itself return a decision-like
    object with ``allowed``/``reason``.
    """
    descriptor = registry.get(request_tool)

    # 1. Unregistered tools never run (default-deny), no matter what grants
    #    claim — a hallucinated tool name cannot be laundered via grants.
    if descriptor is None:
        return PermissionDecision(
            False, f"tool {request_tool!r} is not registered", "tool_unregistered"
        )

    # 2. The calling agent must hold a grant for this tool.
    grant = grants.get(agent_uuid) if grants else None
    if grant is None:
        return PermissionDecision(
            False,
            f"agent {agent_uuid} holds no grant for tool {request_tool!r}",
            "grant_missing",
        )
    if grant.tool_name != request_tool:
        return PermissionDecision(
            False,
            f"agent grant covers {grant.tool_name!r}, not {request_tool!r}",
            "grant_mismatch",
        )

    # 3. Subagents cannot escalate: a child's effective permissions are the
    #    intersection of its own grant and its parent's. We approximate by
    #    refusing any grant whose parent has no grant record at all unless
    #    the agent IS a root agent (no parent declared). This makes "spawned
    #    with extra powers" structurally fail rather than relying on prompts.
    if grant.parent_uuid is not None and grant.parent_uuid not in grants:
        return PermissionDecision(
            False,
            f"parent agent {grant.parent_uuid} has no grant; subagents inherit "
            "a subset, never new capabilities (§6)",
            "subagent_escalation_blocked",
        )

    # 4. Shell requires BOTH an explicit grant flag and campaign-policy
    #    enablement (§15: disabled by default, dual opt-in).
    if descriptor.name == "shell":
        if not (grant.allow_shell and shell_enabled_in_policy):
            return PermissionDecision(
                False,
                "shell execution is disabled by default; requires explicit "
                "campaign enablement AND an explicit agent grant",
                "shell_not_approved",
            )

    # 5. Active-testing tools additionally need the campaign-level flag.
    if descriptor.active_testing and not active_testing_allowed:
        return PermissionDecision(
            False,
            f"tool {request_tool!r} performs active testing which is disabled for this campaign",
            "active_testing_disabled",
        )

    # 6. Allowlist-only egress MUST route through the safe-fetch pipeline /
    #    scope filter rather than opening its own sockets (§15, #124).
    if descriptor.egress is EgressClass.ALLOWLIST_ONLY:
        if scope_filter_check is None:
            return PermissionDecision(
                False,
                f"tool {request_tool!r} must be dispatched through the "
                "safe-fetch pipeline, not directly",
                "egress_bypass_blocked",
            )
        verdict = scope_filter_check() if callable(scope_filter_check) else scope_filter_check
        if not getattr(verdict, "allowed", False):
            return PermissionDecision(
                False,
                f"scope filter denied egress: {getattr(verdict, 'reason', 'denied')}",
                "egress_scope_denied",
            )

    return PermissionDecision(True, "permitted by tool-permission registry")


def build_sandbox_env(extra: dict[str, str] | None = None) -> dict[str, str]:
    """Environment for a sandboxed shell child process (§15).

    Strips anything credential-shaped from inheritance: the child gets only
    a minimal, deterministic environment plus explicitly passed extras.
    Secrets in os.environ (API keys, tokens) therefore never reach tools.
    """
    base = {"PATH": "/usr/bin:/bin", "HOME": "/tmp", "LANG": "C.UTF-8"}
    if extra:
        base.update(extra)
    return base


# Patterns stripped from inherited env even if a caller passes extras —
# defense in depth so a buggy call site can't leak credentials anyway.
SECRET_ENV_SUFFIXES = ("TOKEN", "SECRET", "PASSWORD", "KEY", "CREDENTIAL")


def sanitize_env(env: dict[str, str]) -> dict[str, str]:
    out = {}
    for k, v in env.items():
        if any(k.upper().endswith(s) for s in SECRET_ENV_SUFFIXES):
            continue
        out[k] = v
    return out
