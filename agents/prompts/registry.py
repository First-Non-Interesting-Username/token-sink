"""Versioned prompt/template registry (issue #107, PLAN §4/§6).

Why this exists
---------------
Prompts are safety-critical here: the system's defense against model
misbehavior (PLAN §15) depends on role instructions, and reproducibility
(router decision replay §7.2, audit trail §14) depends on knowing exactly
which prompt version produced a given finding or review. This module gives
every agent-role/subagent prompt an identity:

- ``id`` + semantic ``version`` + ``content_hash`` (sha256 over canonical
  serialization) so two runs with the same version record identical hashes
  in usage events;
- declared required input variables and an expected-output schema reference,
  validated at startup (see :meth:`PromptRegistry.validate`) *before* workers
  launch — a missing/mismatched binding blocks startup;
- strict template rendering (:func:`render`): every substituted variable is
  wrapped in labeled ``<untrusted-data>`` markers and any nested marker
  inside the value is neutralized, so untrusted content passed as data can
  never alter instruction sections (supports #64 untrusted-content labeling).
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass

# Semantic version: major.minor.patch (pre-release tags not needed yet; keep
# the grammar simple and machine-checkable so startup validation can reject
# typos like "1.0" or "v1.0.0").
SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+$")

# Markers wrapping substituted values. A value containing something that
# *looks* like a closing marker is broken up at render time so it cannot
# escape its data context.
_UNTRUSTED_OPEN = "<untrusted-data"
_UNTRUSTED_CLOSE = "</untrusted-data>"


class PromptRegistryError(Exception):
    """Base class for prompt-registry failures."""


class DuplicatePromptError(PromptRegistryError):
    """The same (id, version) pair was registered twice."""


class UnknownPromptError(PromptRegistryError):
    """Lookup by id / id+version found no registered prompt."""


class RenderError(PromptRegistryError):
    """Template rendering failed (missing variable, bad type, etc.)."""


class ValidationError(PromptRegistryError):
    """Startup validation failed; ``errors`` lists every problem found."""

    def __init__(self, errors: list[str]) -> None:
        self.errors = errors
        super().__init__(
            "prompt registry validation failed:\n" + "\n".join(f"  - {e}" for e in errors)
        )


@dataclass(frozen=True)
class PromptTemplate:
    """One immutable, versioned prompt artifact."""

    id: str  # e.g. "role.recon" or "subagent.port-scan"
    version: str  # semver "MAJOR.MINOR.PATCH"
    content: str  # instruction text with {var} placeholders
    role_binding: str | None = None  # agent role this version is bound to
    required_variables: tuple[str, ...] = ()
    expected_output_schema: str | None = None  # schemas/*.schema.json reference
    description: str = ""

    def __post_init__(self) -> None:
        if not self.id:
            raise ValueError("prompt id must be non-empty")
        if not SEMVER_RE.match(self.version):
            raise ValueError(f"version {self.version!r} is not MAJOR.MINOR.PATCH semver")
        if "{" in self.content:
            # Placeholder sanity check happens in render(); nothing else to do,
            # but braces must be balanced for str.format-style parsing.
            self._check_braces()
        object.__setattr__(self, "required_variables", tuple(self.required_variables))

    @staticmethod
    def _check_braces() -> None:
        return None  # str.format raises on unbalanced braces at render time

    def placeholders(self) -> set[str]:
        """Variable names referenced by the template body. Raises ValueError
        on unbalanced braces (caught at registration/render time)."""
        import string

        names: set[str] = set()
        for _, field_name, _, _ in string.Formatter().parse(self.content):
            if field_name is not None:  # None = literal tail, no placeholder
                names.add(field_name.split(".")[0].split("[")[0])
        return names

    def canonical(self) -> str:
        """Stable serialization that the content hash covers."""
        return json.dumps(
            {
                "id": self.id,
                "version": self.version,
                "content": self.content,
                "required_variables": list(self.required_variables),
            },
            sort_keys=True,
            separators=(",", ":"),
        )

    def content_hash(self) -> str:
        """sha256 of the canonical form — recorded in every usage event."""
        return hashlib.sha256(self.canonical().encode("utf-8")).hexdigest()

    def usage_record(self) -> dict[str, str]:
        """The (id, version, hash) triple attached to each LLM call's audit/
        usage event, per issue #107 acceptance: identical versions produce
        identical recorded hashes across runs."""
        return {
            "prompt_id": self.id,
            "prompt_version": self.version,
            "prompt_hash": self.content_hash(),
        }


@dataclass
class PromptUsageEvent:
    """Usage-event linkage appended to each LLM call's audit payload
    (see observability/event_store.py)."""

    campaign_id: str | None
    prompt_id: str
    prompt_version: str
    prompt_hash: str

    def to_payload(self) -> dict[str, str | None]:
        return {
            "campaign_id": self.campaign_id,
            "prompt_id": self.prompt_id,
            "prompt_version": self.prompt_version,
            "prompt_hash": self.prompt_hash,
        }


def render(template: PromptTemplate, variables: dict[str, object]) -> str:
    """Strictly substitute ``{var}`` placeholders with escaped data.

    Rules (per issue #107):

    - Every declared required variable MUST be present; unknown extra keys
      are rejected too, so callers cannot smuggle untracked substitutions.
    - Each value is rendered as labeled untrusted data:
      ``<untrusted-data label="varname">value</untrusted-data>``. Any
      occurrence of the closing marker *inside* the value is split
      (``</untrusted-data>`` → ``< /untrusted-data>``) so hostile content
      cannot close its own wrapper and resume instruction position.
    """
    present = set(variables)
    referenced = template.placeholders()
    missing = sorted(referenced - present)
    extra = sorted(present - referenced)
    errors = []
    if missing:
        errors.append(f"missing required variable(s): {', '.join(missing)}")
    if extra:
        errors.append(f"unknown variable(s) not declared by template: {', '.join(extra)}")
    if errors:
        raise RenderError(f"cannot render {template.id}@{template.version}: " + "; ".join(errors))

    escaped = {k: _escape_untrusted(k, v) for k, v in variables.items()}
    try:
        return template.content.format(**escaped)
    except (KeyError, IndexError, ValueError) as exc:  # unbalanced braces etc.
        raise RenderError(f"malformed template {template.id}@{template.version}: {exc}") from exc


def _escape_untrusted(name: str, value: object) -> str:
    """Wrap a value as labeled untrusted data and neutralize embedded
    closing markers. WHY: prompts are instructions; anything derived from a
    target/webpage/user input is data and must stay visually and structurally
    fenced so prompt injection (#64) cannot rewrite the instruction section."""
    text = "" if value is None else str(value)
    text = text.replace(_UNTRUSTED_CLOSE, "< " + _UNTRUSTED_CLOSE[1:])
    label = name.replace('"', "'")  # keep the attribute well-formed
    return f'{_UNTRUSTED_OPEN} label="{label}">{text}{_UNTRUSTED_CLOSE}'


class PromptRegistry:
    """In-memory registry of versioned prompts with startup validation.

    Persistence can be layered later (SQLite via storage/base.Storage); the
    registry itself only owns identity + lookup + validation so adapters stay
    replaceable (PLAN §4 module-boundary rule).
    """

    def __init__(self) -> None:
        self._prompts: dict[str, dict[str, PromptTemplate]] = {}

    # --- registration ---
    def register(self, template: PromptTemplate) -> None:
        versions = self._prompts.setdefault(template.id, {})
        if template.version in versions:
            raise DuplicatePromptError(f"{template.id}@{template.version} already registered")

        try:
            # Consistency check: declared required_variables must cover the
            # placeholders actually used (and vice versa). Mismatches are
            # caught at registration time rather than mid-run.
            referenced = template.placeholders()
        except ValueError as exc:  # unbalanced braces in the body
            raise ValidationError(
                [f"{template.id}@{template.version}: malformed template: {exc}"]
            ) from exc
        declared = set(template.required_variables)
        problems = []
        if referenced - declared:
            problems.append(
                f"undeclared placeholder(s): {', '.join(sorted(referenced - declared))}"
            )
        if declared - referenced:
            problems.append(
                f"declared but unused variable(s): {', '.join(sorted(declared - referenced))}"
            )
        if problems:
            raise ValidationError([f"{template.id}@{template.version}: {p}" for p in problems])
        versions[template.version] = template

    # --- lookup ---
    def get(self, prompt_id: str, version: str | None = None) -> PromptTemplate:
        versions = self._prompts.get(prompt_id)
        if not versions:
            raise UnknownPromptError(f"unknown prompt id: {prompt_id}")
        if version is None:
            # Latest = highest semver triple.
            key = max(versions, key=lambda v: tuple(int(p) for p in v.split(".")))
            return versions[key]
        if version not in versions:
            raise UnknownPromptError(f"unknown version {version} for prompt {prompt_id}")
        return versions[version]

    def ids(self) -> list[str]:
        return sorted(self._prompts)

    def versions_of(self, prompt_id: str) -> list[str]:
        return sorted(
            self._prompts.get(prompt_id, {}), key=lambda v: tuple(int(p) for p in v.split("."))
        )

    # --- startup validation ---
    def validate_role_bindings(self, bindings: dict[str, tuple[str, str]]) -> None:
        """Check every role → (prompt_id, version) resolves before workers
        launch. Called from config validation/startup (ties into issue #6);
        raises :class:`ValidationError` listing ALL problems at once so an
        operator fixes everything in one round-trip (mirrors config/loader)."""
        errors: list[str] = []
        for role, (pid, ver) in sorted(bindings.items()):
            try:
                tmpl = self.get(pid, ver)
            except UnknownPromptError as exc:
                errors.append(f"role {role!r}: {exc}")
                continue
            if tmpl.role_binding is not None and tmpl.role_binding != role:
                errors.append(
                    f"role {role!r}: prompt {pid}@{ver} is bound to {tmpl.role_binding!r}"
                )
            if tmpl.expected_output_schema:
                # Schema reference format check now; existence check belongs
                # to the schema validator (schemas/validate.py) which runs in
                # CI and at startup separately.
                if not tmpl.expected_output_schema.endswith(".schema.json"):
                    errors.append(
                        f"role {role!r}: expected_output_schema "
                        f"{tmpl.expected_output_schema!r} is not a *.schema.json reference"
                    )
        if errors:
            raise ValidationError(errors)

    def summary(self) -> list[dict[str, object]]:
        """Rows for `system prompts list`."""
        rows = []
        for pid in self.ids():
            for ver in self.versions_of(pid):
                t = self._prompts[pid][ver]
                rows.append(
                    {
                        "id": pid,
                        "version": ver,
                        "hash": t.content_hash(),
                        "role": t.role_binding,
                        "variables": list(t.required_variables),
                        "output_schema": t.expected_output_schema,
                        "description": t.description,
                    }
                )
        return rows
