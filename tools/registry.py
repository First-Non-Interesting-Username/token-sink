"""Tool permission registry & enforcement (PLAN §6, §15, §18 — issue #155).

Every callable tool exposes a versioned, machine-readable signature; the
:class:`ToolRegistry` is the single source of truth for what exists and what
arguments it accepts. Validation happens BEFORE dispatch: a model that
hallucinates a tool name or emits malformed arguments gets a structured
rejection event back as bounded feedback — never a crash, and never an
execution.

This is also a safety surface (§15): policy is enforced in code independent
of model instructions, so an unregistered tool simply cannot run.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any


class ParamKind(enum.Enum):
    """Types a tool parameter can take (kept small on purpose)."""

    STRING = "string"
    INTEGER = "integer"
    NUMBER = "number"
    BOOLEAN = "boolean"
    STRING_LIST = "string_list"
    OBJECT = "object"


# Python types accepted for each ParamKind. bool is excluded from integer /
# number deliberately: isinstance(True, int) is True in Python and letting a
# bool slip into a numeric argument changes semantics silently.
_KIND_PYTHON_TYPES: dict[ParamKind, tuple[type, ...]] = {
    ParamKind.STRING: (str,),
    ParamKind.INTEGER: (int,),
    ParamKind.NUMBER: (int, float),
    ParamKind.BOOLEAN: (bool,),
    ParamKind.STRING_LIST: (list,),
    ParamKind.OBJECT: (dict,),
}


@dataclass(frozen=True)
class ToolParam:
    """One declared tool parameter."""

    name: str
    kind: ParamKind
    required: bool = False
    default: Any = None
    description: str = ""


@dataclass(frozen=True)
class ToolSignature:
    """Versioned, machine-readable description of one callable tool.

    ``version`` bumps when the signature changes shape so callers can pin
    compatibility (same convention as the record schemas' schema_version).
    """

    name: str
    version: int
    description: str
    params: tuple[ToolParam, ...]
    returns: dict[str, Any]  # lightweight return-schema descriptor


@dataclass(frozen=True)
class Rejection:
    """A structured rejection returned to the model as feedback (§6).

    ``code`` values are stable strings suitable for observability counters:
    unknown_tool, unknown_parameter, missing_required, wrong_type,
    payload_too_large, registry_version_mismatch.
    """

    code: str
    message: str
    details: list[str] = field(default_factory=list)

    def as_feedback(self) -> dict[str, Any]:
        """The dict handed back to the model instead of a tool result."""
        return {"rejected": True, "code": self.code, "message": self.message}


class ToolRegistry:
    """Single source of truth for callable tools.

    ``strict`` controls undeclared-parameter handling (issue #155): in strict
    mode extra parameters are a rejection rather than being silently dropped —
    silent dropping can change semantics (e.g. a dropped ``dry_run=False``).
    """

    def __init__(self, strict: bool = True, max_payload_bytes: int = 64_000) -> None:
        self._tools: dict[str, ToolSignature] = {}
        self.strict = strict
        self.max_payload_bytes = max_payload_bytes

    def register(self, signature: ToolSignature, *, replace: bool = False) -> None:
        if not replace and signature.name in self._tools:
            raise ValueError(
                f"tool {signature.name!r} already registered "
                "(pass replace=True to bump it deliberately)"
            )
        self._tools[signature.name] = signature

    def get(self, name: str) -> ToolSignature | None:
        return self._tools.get(name)

    def names(self) -> list[str]:
        return sorted(self._tools)

    def describe_for_prompt(self) -> list[dict[str, Any]]:
        """Machine-readable listing agents embed in prompts so models only
        ever see tools that actually exist."""
        return [
            {
                "name": s.name,
                "version": s.version,
                "description": s.description,
                "params": [
                    {
                        "name": p.name,
                        "kind": p.kind.value,
                        "required": p.required,
                        "description": p.description,
                    }
                    for p in s.params
                ],
            }
            for s in (self._tools[n] for n in self.names())
        ]

    # --- validation ---------------------------------------------------------

    def validate_call(
        self, name: str, arguments: dict[str, Any]
    ) -> tuple[dict[str, Any] | None, Rejection | None]:
        """Validate one attempted call against its registered signature.

        Returns ``(normalized_arguments, None)`` when valid, or
        ``(None, rejection)`` otherwise. Normalization fills declared
        defaults for omitted optional params — nothing else is altered;
        undeclared keys are never passed through.
        """
        sig = self.get(name)
        if sig is None:
            return None, Rejection(
                "unknown_tool",
                f"tool {name!r} does not exist; available tools: " + ", ".join(self.names()),
            )

        if not isinstance(arguments, dict):
            return None, Rejection(
                "wrong_type",
                "tool arguments must be a JSON object",
                [f"got {_kind_name(arguments)}"],
            )

        size = _payload_size(arguments)
        if size > self.max_payload_bytes:
            return None, Rejection(
                "payload_too_large",
                f"arguments exceed max payload of {self.max_payload_bytes} bytes",
                [f"{size} bytes"],
            )

        declared = {p.name: p for p in sig.params}
        errors: list[str] = []

        for key in arguments:
            if key not in declared:
                if self.strict:
                    errors.append(f"undeclared parameter {key!r}")
                # non-strict still drops it — never forwarded unvalidated

        for param in sig.params:
            if param.name in arguments:
                value = arguments[param.name]
                allowed = _KIND_PYTHON_TYPES[param.kind]
                bad_type = not isinstance(value, allowed) or (
                    isinstance(value, bool) and param.kind is not ParamKind.BOOLEAN
                )
                if bad_type:
                    errors.append(
                        f"parameter {param.name!r} expects "
                        f"{param.kind.value}, got {_kind_name(value)}"
                    )
                elif param.kind is ParamKind.STRING_LIST and not all(
                    isinstance(v, str) for v in value
                ):
                    errors.append(f"parameter {param.name!r} must contain only strings")
            elif param.required:
                errors.append(f"required parameter {param.name!r} missing")

        if errors:
            return None, Rejection("invalid_arguments", "; ".join(errors), errors)

        normalized = {p.name: arguments[p.name] for p in sig.params if p.name in arguments}
        for param in sig.params:
            if param.name not in normalized and not param.required:
                normalized[param.name] = param.default
        return normalized, None


def _kind_name(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    return type(value).__name__


def _payload_size(arguments: dict[str, Any]) -> int:
    import json

    try:
        return len(json.dumps(arguments, default=str).encode())
    except (TypeError, ValueError):
        return 2**31  # unserializable → treat as oversized
