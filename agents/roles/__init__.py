"""Agent role registry (issue #161): declarative role definitions bound to
versioned prompt templates (see agents/prompts, issue #107)."""

from .registry import (
    KNOWN_TOOLS,
    LIFECYCLE_STAGES,
    AgentRole,
    DuplicateRoleError,
    RoleRegistry,
    RoleRegistryError,
    SubagentPolicy,
    default_roles,
)

__all__ = [
    "AgentRole",
    "DuplicateRoleError",
    "KNOWN_TOOLS",
    "LIFECYCLE_STAGES",
    "RoleRegistry",
    "RoleRegistryError",
    "SubagentPolicy",
    "default_roles",
]
