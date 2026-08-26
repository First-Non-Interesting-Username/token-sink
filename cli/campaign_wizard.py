"""Campaign configuration wizard & scope validation UX (issue #171, PLAN §5).

Campaign creation is the highest-stakes user flow: a bad scope undermines
every downstream safety guarantee. This wizard therefore refuses to save an
invalid or ambiguous draft — mirroring the §5 principle that agents refuse to
start when scope is missing or ambiguous.

Three layers:

1. ``validate_campaign_draft`` — pure validation over a plain dict draft.
   Reuses ``policy.scope.TargetSpec`` parsing (the same matcher the policy
   engine enforces at runtime) so what you validate is what gets enforced.
2. ``build_manifest`` — produces a campaign manifest dict matching
   ``schemas/campaign.schema.json``; only valid drafts may be converted.
3. ``run_wizard`` — interactive guided prompt loop (CLI); every answer is
   validated live before it is accepted.

Non-interactive callers (tests, future UI) use layer 1 directly.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from policy.scope import ACTIVE_TEST_CLASSES, TargetSpec


class WizardError(Exception):
    """Raised when a draft cannot be validated or converted."""


# HTTP methods we consider well-formed for scope config.
KNOWN_METHODS = {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}

REQUIRED_STR_FIELDS = ("name", "authorization_reference")


def _parse_targets(raw: Any, label: str, errors: list[str]) -> list[TargetSpec]:
    """Parse a list of target strings into TargetSpecs, collecting errors."""
    if raw is None:
        raw = []
    if not isinstance(raw, list):
        errors.append(f"{label} must be a list of target strings")
        return []
    specs: list[TargetSpec] = []
    for item in raw:
        if not isinstance(item, str) or not item.strip():
            errors.append(f"{label} contains an empty/non-string entry: {item!r}")
            continue
        try:
            spec = TargetSpec(value=item.strip())
            kind = spec._resolved_kind()
            # Force resolution now so malformed entries fail at input time
            # rather than silently matching nothing at enforcement time.
            import ipaddress
            import re

            if kind == "cidr" or (
                "/" in spec.value and "://" not in spec.value and _looks_like_cidr(spec.value)
            ):
                ipaddress.ip_network(spec.value, strict=False)
            elif kind == "domain":
                # A domain entry must be a plausible hostname: non-empty
                # labels, no spaces, valid characters.
                host = spec.value.lower().rstrip(".")
                if not re.fullmatch(
                    r"[a-z0-9]([a-z0-9-]*[a-z0-9])?"
                    r"(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+",
                    host,
                ):
                    raise ValueError(f"{spec.value!r} is not a valid hostname")
        except ValueError as exc:
            errors.append(f"{label}: invalid target {item!r} ({exc})")
            continue
        specs.append(spec)
    return specs


def _overlapping(in_spec: TargetSpec, out_spec: TargetSpec) -> bool:
    """Conservative overlap check between an in-scope and out-of-scope entry.

    Uses probe URLs: if either side's representative URL matches the other's
    spec, the entries can collide. Domain wildcards make this heuristic, so
    any detected collision is surfaced as a warning the operator must fix.
    """
    probes = [f"https://{in_spec.value.rstrip('/')}/", in_spec.value]
    for probe in probes:
        try:
            if out_spec.matches_url(probe):
                return True
        except ValueError:
            continue
    return False


def _looks_like_cidr(value: str) -> bool:
    """True for strings shaped like IP/prefix (e.g. '10.0.0.0/24'). Used to
    catch malformed CIDRs that the TargetSpec name-heuristic would swallow."""
    addr, _, prefix = value.partition("/")
    return (
        prefix.isdigit()
        and all(p.isdigit() and 0 <= int(p) <= 255 for p in addr.split("."))
        and len(addr.split(".")) == 4
    )


def validate_campaign_draft(draft: dict[str, Any]) -> list[str]:
    """Validate a campaign draft dict; returns a list of error strings.

    Empty list means the draft is safe to convert into a manifest.
    """
    errors: list[str] = []
    if not isinstance(draft, dict):
        return ["draft must be a mapping"]

    # 1. Required identity fields.
    for f in REQUIRED_STR_FIELDS:
        v = draft.get(f)
        if not isinstance(v, str) or not v.strip():
            errors.append(f"{f} is required")

    name = str(draft.get("name", "")).strip()
    if name.lower() in {"untitled", "test", "campaign"}:
        errors.append(f"name {name!r} looks like a placeholder; be specific")

    # 2. Scope entries parse into real TargetSpecs.
    in_scope = _parse_targets(draft.get("in_scope"), "in_scope", errors)
    out_scope = _parse_targets(draft.get("out_of_scope"), "out_of_scope", errors)

    if not in_scope:
        errors.append("at least one in_scope target is required")
        return errors

    # §5 refusal principle: active campaigns must say what is OFF limits.
    active = bool(draft.get("active_testing_enabled", False))
    if not out_scope:
        errors.append(
            "out_of_scope must not be empty — an explicit exclusion list is "
            "mandatory (refuse-when-ambiguous, PLAN §5)"
        )

    # 3. In/out overlap detection: an out-of-scope entry fully covered by (or
    # covering) an in-scope entry makes the boundary ambiguous.
    for o in out_scope:
        for i in in_scope:
            if _overlapping(i, o):
                errors.append(
                    f"scope overlap: in-scope {i.value!r} conflicts with "
                    f"out-of-scope {o.value!r}; carve out explicitly"
                )
                break

    # 4. Methods / test classes.
    allowed_methods = draft.get("allowed_methods")
    if allowed_methods is not None:
        if not isinstance(allowed_methods, list):
            errors.append("allowed_methods must be a list")
        else:
            bad = [m for m in allowed_methods if m not in KNOWN_METHODS]
            if bad:
                errors.append(f"unknown HTTP methods: {bad}")

    classes = draft.get("allowed_test_classes") or []
    if not isinstance(classes, list):
        errors.append("allowed_test_classes must be a list")
        classes = []
    unknown = [c for c in classes if c not in ACTIVE_TEST_CLASSES]
    if unknown:
        errors.append(f"unknown test classes: {unknown}")
    if active and not classes:
        errors.append("active_testing_enabled requires at least one allowed_test_class")
    if classes and not active:
        errors.append("active test classes listed but active_testing_enabled is false")

    # 5. Numeric limits must be positive when present.
    for f in (
        "max_request_rate_per_target",
        "max_concurrency_per_target",
        "max_duration_seconds",
        "token_budget",
        "tool_budget",
    ):
        v = draft.get(f)
        if v is not None:
            if not isinstance(v, (int, float)) or isinstance(v, bool) or v <= 0:
                errors.append(f"{f} must be a positive number")

    prohibited = draft.get("prohibited_actions") or []
    if not isinstance(prohibited, list):
        errors.append("prohibited_actions must be a list")

    approval = draft.get("human_approval_required_for") or []
    if not isinstance(approval, list):
        errors.append("human_approval_required_for must be a list")

    return errors


def _target_ref(spec: TargetSpec) -> dict[str, str]:
    """Map a TargetSpec onto the schema's target_ref object shape
    (common.schema.json $defs/target_ref: {kind, identifier})."""
    kind = spec._resolved_kind()
    mapping = {
        "domain": "domain",
        "url": "url",
        "cidr": "domain",  # CIDR ranges are network targets; nearest schema kind
    }
    return {"kind": mapping.get(kind, "application"), "identifier": spec.value}


def build_manifest(draft: dict[str, Any]) -> dict[str, Any]:
    """Convert a VALIDATED draft into a campaign manifest compatible with
    schemas/campaign.schema.json. Raises WizardError on invalid drafts —
    an invalid or ambiguous scope can never be saved."""
    errors = validate_campaign_draft(draft)
    if errors:
        raise WizardError("invalid campaign draft: " + "; ".join(errors))

    now = datetime.now(UTC).isoformat()
    manifest: dict[str, Any] = {
        "schema_version": 1,
        "record_type": "campaign",
        "campaign_uuid": str(uuid.uuid4()),
        "name": draft["name"].strip(),
        "authorization_reference": draft["authorization_reference"].strip(),
        "program_name": draft.get("program_name") or "",
        "in_scope_targets": [
            _target_ref(t) for t in _parse_targets(draft.get("in_scope"), "in_scope", [])
        ],
        "out_of_scope_targets": [
            _target_ref(t) for t in _parse_targets(draft.get("out_of_scope"), "out_of_scope", [])
        ],
        "prohibited_actions": draft.get("prohibited_actions") or [],
        "active_testing_enabled": bool(draft.get("active_testing_enabled")),
        "created_at": now,
        "updated_at": now,
    }
    optional_map = {
        "allowed_methods": "allowed_http_methods",
        "allowed_test_classes": "allowed_test_classes",
        "max_request_rate_per_target": "max_request_rate_per_target",
        "max_concurrency_per_target": "max_concurrency_per_target",
        "max_duration_seconds": "max_duration_seconds",
        "token_budget": "token_budget",
        "tool_budget": "tool_budget",
        "human_approval_required_for": "human_approval_required_for",
        "retention_settings": "retention_settings",
        "data_handling": "data_handling",
    }
    for src, dst in optional_map.items():
        v = draft.get(src)
        if v:
            manifest[dst] = v
    return manifest


# -- interactive wizard ------------------------------------------------------


def _ask(prompt: str, current: Any = None) -> str | None:
    """Prompt helper returning None on empty input (keep default)."""
    suffix = f" [{current}] " if current not in (None, "") else ": "
    try:
        answer = input(prompt + suffix)
    except EOFError:
        return None
    return answer.strip() or None


def run_wizard(draft: dict[str, Any] | None = None) -> dict[str, Any]:
    """Guided interactive campaign creation. Returns the built manifest.

    Every field is validated live: the loop refuses to advance past a step
    whose answer fails validation, and a final full-draft check gates saving.
    """
    d: dict[str, Any] = dict(draft or {})

    print("Campaign configuration wizard — ctrl+c aborts.\n")
    while True:
        v = _ask("Campaign name", d.get("name"))
        if v:
            d["name"] = v
        errs = [e for e in validate_campaign_draft(d) if "name" in e]
        for e in errs:
            print(f"  ! {e}")
        if d.get("name") and not errs:
            break

    while True:
        v = _ask("Authorization reference / program", d.get("authorization_reference"))
        if v:
            d["authorization_reference"] = v
        if d.get("authorization_reference"):
            break
        print("  ! authorization_reference is required")

    while True:
        raw = _ask("In-scope targets (comma-separated)", ", ".join(d.get("in_scope") or []) or None)
        if raw:
            d["in_scope"] = [s.strip() for s in raw.split(",") if s.strip()]
        errs = [e for e in validate_campaign_draft(d) if e.startswith("in_scope")]
        for e in errs:
            print(f"  ! {e}")
        if d.get("in_scope") and not errs:
            break

    while True:
        raw = _ask(
            "Out-of-scope exclusions (comma-separated)",
            ", ".join(d.get("out_of_scope") or []) or None,
        )
        if raw is not None:
            d["out_of_scope"] = [s.strip() for s in raw.split(",") if s.strip()]
        errs = [e for e in validate_campaign_draft(d) if "out_of_scope" in e or "overlap" in e]
        for e in errs:
            print(f"  ! {e}")
        if not errs:
            break

    active_raw = _ask(
        "Enable active testing? y/N",
        "y" if d.get("active_testing_enabled") else "N",
    )
    active = bool(active_raw and active_raw.lower().startswith("y"))
    d["active_testing_enabled"] = active

    if active:
        while True:
            raw = _ask(
                "Allowed active test classes (comma-separated)",
                ", ".join(d.get("allowed_test_classes") or []) or None,
            )
            if raw is not None:
                d["allowed_test_classes"] = [s.strip() for s in raw.split(",") if s.strip()]
            errs = [e for e in validate_campaign_draft(d) if "test class" in e]
            for e in errs:
                print(f"  ! {e}")
            if not errs:
                break

    # Final gate: the complete draft must validate before a manifest exists.
    errors = validate_campaign_draft(d)
    if errors:
        raise WizardError("cannot save invalid campaign: " + "; ".join(errors))
    return build_manifest(d)
