#!/usr/bin/env python3
"""Dependency-free sanity checks over schemas/*.schema.json.

Checks:
1. Every schema file parses as JSON.
2. Every schema declares $schema (draft 2020-12), $id, title, and a
   `record_type` const that matches its filename.
3. Cross-file $refs (`<file>.schema.json#/$defs/...`) resolve to real files
   and real definitions.
4. Every record schema requires `schema_version` and `record_type`.

Once the project gains dependencies, replace/augment this with `jsonschema`
based tests that also validate example records (see docs/schemas.md).
"""

import json
import re
import sys
from pathlib import Path

SCHEMA_DIR = Path(__file__).resolve().parent.parent / "schemas"
REF_RE = re.compile(r"^([A-Za-z0-9_.-]+\.schema\.json)?#(?:/\$defs/([A-Za-z0-9_-]+))?$")


def main() -> int:
    errors: list[str] = []
    schemas = {}
    for path in sorted(SCHEMA_DIR.glob("*.schema.json")):
        try:
            doc = json.loads(path.read_text())
        except json.JSONDecodeError as exc:
            errors.append(f"{path.name}: invalid JSON: {exc}")
            continue
        schemas[path.name] = doc

        if doc.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
            errors.append(f"{path.name}: missing/incorrect $schema")
        if "$id" not in doc or not doc["$id"].endswith(path.name):
            errors.append(f"{path.name}: $id missing or does not match filename")
        if "title" not in doc:
            errors.append(f"{path.name}: missing title")

        req = doc.get("required", [])
        if "record_type" in doc.get("properties", {}):
            # Record schemas only; common.schema.json defines shared $defs.
            expected = path.name.replace(".schema.json", "")
            rt = doc["properties"]["record_type"]
            if rt.get("const") != expected:
                errors.append(
                    f"{path.name}: record_type const {rt.get('const')!r} != {expected!r}"
                )
            for key in ("schema_version", "record_type"):
                if key not in req:
                    errors.append(f"{path.name}: {key} not in required list")

    # Second pass: resolve $refs only after every file is loaded, so
    # forward/cross-file references (e.g. -> common.schema.json) resolve.
    for name, doc in schemas.items():
        path = SCHEMA_DIR / name

        def walk(node):
            if isinstance(node, dict):
                if "$ref" in node:
                    m = REF_RE.match(node["$ref"])
                    if not m:
                        errors.append(f"{path.name}: unparseable $ref {node['$ref']!r}")
                    else:
                        target_file = m.group(1) or path.name
                        def_name = m.group(2)
                        if target_file not in schemas and target_file != path.name:
                            errors.append(
                                f"{path.name}: $ref to missing file {target_file}"
                            )
                        elif def_name:
                            target = schemas.get(target_file, doc)
                            if def_name not in target.get("$defs", {}):
                                errors.append(
                                    f"{path.name}: $ref to missing $defs/{def_name} "
                                    f"in {target_file}"
                                )
                for v in node.values():
                    walk(v)
            elif isinstance(node, list):
                for v in node:
                    walk(v)

        walk(doc)

    common = schemas.get("common.schema.json")
    if not common or "$defs" not in common:
        errors.append("common.schema.json: missing or has no $defs")

    count = len([f for f in SCHEMA_DIR.glob("*.schema.json")])
    print(f"Checked {count} schemas in {SCHEMA_DIR}")
    if errors:
        for e in errors:
            print(f"ERROR: {e}", file=sys.stderr)
        return 1
    print("All schema sanity checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
