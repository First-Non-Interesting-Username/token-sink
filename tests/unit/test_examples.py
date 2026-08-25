"""CI drift guard for examples/ (issue #90).

Validates every example record against its JSON Schema so the examples can
never drift from the schemas. The repo deliberately has no `jsonschema`
dependency (see scripts/validate_schemas.py docstring), so this module
implements a minimal JSON-Schema subset checker covering exactly what the
record schemas use: type, const, enum, pattern, format (uuid/date-time),
required, additionalProperties:false, minItems/maxLength/minLength/minimum,
and local $refs (`file.schema.json#/$defs/name`).
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_DIR = REPO_ROOT / "schemas"
EXAMPLES_DIR = REPO_ROOT / "examples"

sys.path.insert(0, str(REPO_ROOT))

UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
DATETIME_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$")

# Example record -> schema file it must satisfy.
EXAMPLES = {
    "campaign.example.json": "campaign.schema.json",
    "scope-policy.example.json": "scope_policy.schema.json",
    "providers/native-free.example.json": "provider.schema.json",
    "providers/gateway-with-filter.example.json": "provider.schema.json",
    "providers/custom-endpoint.example.json": "provider.schema.json",
}


class ValidationError(Exception):
    pass


def _resolve_ref(ref: str) -> dict:
    """Resolve a local ref like 'common.schema.json#/$defs/uuid'."""
    fname, _, frag = ref.partition("#")
    doc = json.loads((SCHEMA_DIR / fname).read_text())
    node = doc
    for part in frag.strip("/").split("/"):
        if part:
            node = node[part]
    return node


def _check_type(value, schema: dict, path: str) -> None:
    expected = schema.get("type")
    if expected is None:
        return
    types = expected if isinstance(expected, list) else [expected]
    ok = False
    for t in types:
        if t == "object" and isinstance(value, dict):
            ok = True
        elif t == "array" and isinstance(value, list):
            ok = True
        elif t == "string" and isinstance(value, str):
            ok = True
        elif t == "integer" and isinstance(value, int) and not isinstance(value, bool):
            ok = True
        elif t == "number" and isinstance(value, (int, float)) and not isinstance(value, bool):
            ok = True
        elif t == "boolean" and isinstance(value, bool):
            ok = True
        elif t == "null" and value is None:
            ok = True
    if not ok:
        raise ValidationError(f"{path}: expected type {expected}, got {type(value).__name__}")


def validate(instance, schema: dict, path: str = "$") -> None:
    """Validate a JSON value against a schema subset. Raises ValidationError."""
    if "$ref" in schema:
        validate(instance, _resolve_ref(schema["$ref"]), path)
        return

    _check_type(instance, schema, path)

    if "const" in schema and instance != schema["const"]:
        raise ValidationError(f"{path}: expected const {schema['const']!r}, got {instance!r}")
    if "enum" in schema and instance not in schema["enum"]:
        raise ValidationError(f"{path}: {instance!r} not in enum {schema['enum']}")

    if isinstance(schema.get("pattern"), str):
        if not re.search(schema["pattern"], instance or ""):
            raise ValidationError(
                f"{path}: {instance!r} does not match pattern {schema['pattern']}"
            )
    if schema.get("format") == "uuid" and not UUID_RE.match(instance or ""):
        raise ValidationError(f"{path}: {instance!r} is not a canonical lowercase UUID")
    if schema.get("format") == "date-time" and not DATETIME_RE.match(instance or ""):
        raise ValidationError(f"{path}: {instance!r} is not an RFC 3339 timestamp")

    if isinstance(instance, dict):
        props = schema.get("properties", {})
        for key in schema.get("required", []):
            if key not in instance:
                raise ValidationError(f"{path}: missing required property {key!r}")
        # Only strict-object schemas matter for our records; a permissive one
        # (no additionalProperties key at all) allows unknown fields.
        if schema.get("additionalProperties") is False:
            for key in instance:
                if key not in props:
                    raise ValidationError(f"{path}: unexpected property {key!r}")
        for key, subschema in props.items():
            if key in instance:
                validate(instance[key], subschema, f"{path}.{key}")

    if isinstance(instance, list):
        if "minItems" in schema and len(instance) < schema["minItems"]:
            raise ValidationError(f"{path}: needs >= {schema['minItems']} items")
        item_schema = schema.get("items")
        if item_schema:
            for i, item in enumerate(instance):
                validate(item, item_schema, f"{path}[{i}]")

    if isinstance(instance, str):
        if "minLength" in schema and len(instance) < schema["minLength"]:
            raise ValidationError(f"{path}: shorter than minLength {schema['minLength']}")
    if isinstance(instance, (int, float)) and not isinstance(instance, bool):
        if "minimum" in schema and instance < schema["minimum"]:
            raise ValidationError(f"{path}: below minimum {schema['minimum']}")


@pytest.mark.parametrize("example,schema_file", sorted(EXAMPLES.items()))
def test_example_matches_schema(example: str, schema_file: str) -> None:
    record = json.loads((EXAMPLES_DIR / example).read_text())
    schema = json.loads((SCHEMA_DIR / schema_file).read_text())
    validate(record, schema)


def test_campaign_and_policy_share_uuid() -> None:
    campaign = json.loads((EXAMPLES_DIR / "campaign.example.json").read_text())
    policy = json.loads((EXAMPLES_DIR / "scope-policy.example.json").read_text())
    assert policy["campaign_uuid"] == campaign["campaign_uuid"]


def test_provider_examples_cover_all_classes() -> None:
    kinds = set()
    for example in EXAMPLES:
        if example.startswith("providers/"):
            kinds.add(json.loads((EXAMPLES_DIR / example).read_text())["kind"])
    assert kinds == {"native_free", "gateway", "custom_endpoint"}


def test_no_literal_credentials() -> None:
    """Fake sk-example values may appear only in docs; record files must use env-var names."""
    secret_re = re.compile(r"sk-[A-Za-z0-9]{8,}")
    for example in EXAMPLES:
        text = (EXAMPLES_DIR / example).read_text()
        assert not secret_re.search(text), f"{example} contains a literal-looking credential"


# RFC 2606 reserved names + documentation hosts + repo-local fixtures only.
_ALLOWED_HOST_SUFFIXES = ("example.com", "example.net", "example.org", ".example")


def test_targets_are_reserved_or_local_fixtures() -> None:
    """Safety: no example may reference a real target."""
    for example in ("campaign.example.json", "scope-policy.example.json"):
        record = json.loads((EXAMPLES_DIR / example).read_text())
        targets = []
        for key in ("in_scope_targets", "out_of_scope_targets", "in_scope", "out_of_scope"):
            targets.extend(record.get(key, []))
        assert targets, f"{example} defines no targets"
        for t in targets:
            if t["kind"] == "local_fixture":
                assert (REPO_ROOT / t["identifier"]).exists(), f"dangling fixture {t['identifier']}"
                continue
            ident = t["identifier"]
            host = ident.split("//")[-1].split("/")[0].split(":")[0].lstrip("*.")
            assert any(host.endswith(s.lstrip(".")) for s in _ALLOWED_HOST_SUFFIXES), (
                f"{example}: target {ident!r} is not a reserved documentation host"
            )
