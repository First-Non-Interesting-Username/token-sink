"""Structured-output validation for agent results (PLAN §6, §18).

Every agent/subagent result must validate against its declared output schema
(the versioned JSON Schemas under ``schemas/``) before the orchestrator
accepts it. Malformed model output is an explicit failure class
(``FailureClass.MALFORMED_OUTPUT``, §18): it is classified, never silently
coerced, and the raw input+output are preserved for diagnosis.

Design rules:

- Validation is structural and dependency-light: ``jsonschema`` for the
  draft-2020-12 checks, plus a truncation heuristic because truncated LLM
  JSON frequently parses as valid-but-wrong or fails with a confusing error.
- Errors are reported as a flat list of human-readable strings so callers can
  attach them to a ``FailureRecord`` without depending on jsonschema types.
- This module never mutates or "repairs" payloads — acceptance is binary.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator
from jsonschema.validators import validator_for

SCHEMA_DIR = Path(__file__).resolve().parent.parent / "schemas"

# Record types an agent can emit as its result, mapped to their schema files.
RESULT_SCHEMAS: dict[str, str] = {
    "agent": "agent.schema.json",
    "review": "review.schema.json",
    "poc": "poc.schema.json",
    "finding": "finding.schema.json",
    "search_result": "search_result.schema.json",
    "usage_event": "usage_event.schema.json",
    "task": "task.schema.json",
}


@dataclass(frozen=True)
class ValidationResult:
    """Outcome of validating one result payload."""

    valid: bool
    errors: list[str] = field(default_factory=list)


class SchemaRegistry:
    """Loads and caches schemas/*.schema.json; resolves cross-file $refs.

    Cross-file refs use the repo convention ``<file>.schema.json#/...``
    (see schemas/README.md), which jsonschema resolves via a referring
    document store keyed by filename.
    """

    def __init__(self, schema_dir: Path = SCHEMA_DIR) -> None:
        self._dir = schema_dir
        self._cache: dict[str, dict[str, Any]] = {}

    def get(self, name: str) -> dict[str, Any]:
        """Return the parsed schema for `name` like \"agent\" or
        \"agent.schema.json\"."""
        filename = name if name.endswith(".schema.json") else f"{name}.schema.json"
        if filename not in self._cache:
            path = self._dir / filename
            try:
                doc = json.loads(path.read_text())
            except FileNotFoundError as exc:
                raise KeyError(f"unknown schema: {filename}") from exc
            except json.JSONDecodeError as exc:
                # A broken schema file is a repo bug, not agent misbehavior:
                # fail loudly instead of accepting unvalidated output.
                raise ValueError(f"schema {filename} is not valid JSON: {exc}") from exc
            self._cache[filename] = doc
        return self._cache[filename]

    def validator(self, name: str) -> Draft202012Validator:
        """Build a validator for `name`, wiring cross-file $ref resolution."""
        schema = self.get(name)
        cls = validator_for(schema)
        # All repo schemas declare draft 2020-12; enforce it so a stray
        # $schema bump doesn't silently change validation semantics.
        if cls is not Draft202012Validator:
            raise ValueError(f"schema {name} does not declare draft 2020-12")
        # Cross-file refs (e.g. common.schema.json#/$defs/uuid) resolve via a
        # RefResolver whose store maps filenames -> parsed schemas. Preload
        # every known schema so refs to files outside RESULT_SCHEMAS also work.
        from jsonschema import RefResolver  # small, lazy import

        store = {
            fname: self.get(fname[: -len(".schema.json")])
            for fname in sorted(p.name for p in self._dir.glob("*.schema.json"))
        }
        resolver = RefResolver(base_uri="", referrer=schema, store=store)
        return Draft202012Validator(schema, resolver=resolver)

    def validate(self, record_type: str, payload: Any) -> ValidationResult:
        """Validate `payload` against the schema for `record_type`.

        Returns a ValidationResult; never raises for invalid payloads —
        malformed output is a classified failure (§18), not an exception in
        the caller's control flow.
        """
        try:
            validator = self.validator(record_type)
        except (KeyError, ValueError) as exc:
            return ValidationResult(valid=False, errors=[str(exc)])
        errors = sorted(
            f"{'/'.join(str(p) for p in err.absolute_path) or '<root>'}: {err.message}"
            for err in validator.iter_errors(payload)
        )
        return ValidationResult(valid=not errors, errors=errors)


def detect_truncation(raw_output: str) -> str | None:
    """Heuristic for truncated LLM output: returns a reason string or None.

    Truncated JSON often fails parsing with misleading errors (or worse,
    parses after silent repair); flagging it explicitly keeps the failure
    class accurate (model-quality/truncation rather than transient).
    """
    text = raw_output.strip()
    if not text:
        return "empty output"
    # Unbalanced delimiters at end-of-text strongly suggest mid-stream cutoff.
    pairs = {"{": "}", "[": "]"}
    stack: list[str] = []
    in_string = False
    escape = False
    last_significant = ""
    for ch in text:
        if in_string:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
        elif ch in pairs:
            stack.append(ch)
        elif ch in pairs.values():
            if not stack:
                return None  # genuinely malformed, not truncated
            stack.pop()
        if not ch.isspace():
            last_significant = ch
    if in_string:
        return "output ends inside an unterminated string"
    if stack:
        return f"unclosed delimiter(s): {''.join(stack)}"
    if last_significant in pairs.keys() | pairs.values():
        return None
    # Non-delimiter trailing character (e.g. cut mid-token) is suspicious only
    # when the output looks JSON-ish but doesn't parse.
    if text[0] in "{[":
        try:
            json.loads(text)
        except json.JSONDecodeError:
            return "JSON-like output that fails to parse (possible mid-token cut)"
    return None


def classify_result(
    raw_output: str,
    record_type: str,
    registry: SchemaRegistry | None = None,
) -> tuple[Any | None, ValidationResult]:
    """Parse + validate one agent result.

    Returns ``(payload, result)``. On any failure ``payload is None`` and
    ``result.errors`` explains why — callers map this onto
    ``FailureClass.MALFORMED_OUTPUT`` and preserve the redacted raw output on
    the FailureRecord. No coercion, no repair, no retry here (§18).
    """
    registry = registry or SchemaRegistry()
    truncation = detect_truncation(raw_output)
    if truncation is not None:
        return None, ValidationResult(valid=False, errors=[f"truncated output: {truncation}"])
    try:
        payload = json.loads(raw_output)
    except json.JSONDecodeError as exc:
        return None, ValidationResult(valid=False, errors=[f"invalid JSON: {exc}"])
    if not isinstance(payload, dict):
        return None, ValidationResult(
            valid=False, errors=[f"expected object payload, got {type(payload).__name__}"]
        )
    declared = payload.get("record_type")
    if declared != record_type:
        return None, ValidationResult(
            valid=False,
            errors=[
                f"record_type mismatch: payload declares {declared!r}, expected {record_type!r}"
            ],
        )
    result = registry.validate(record_type, payload)
    return (payload if result.valid else None), result
