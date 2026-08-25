"""`system prompts` CLI (issue #107, PLAN §17).

Non-interactive, automation-friendly listing/inspection of registered prompt
versions, mirroring the style of policy/cli.py. The application entrypoint
supplies the shared PromptRegistry instance via :func:`build_parser`.
"""

from __future__ import annotations

import argparse
import json
import sys

from agents.prompts import PromptRegistry, UnknownPromptError


def build_parser(registry: PromptRegistry) -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="system prompts", description="Prompt registry inspection")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("list", help="List all registered prompt versions")

    ip = sub.add_parser("inspect", help="Show one prompt version in detail")
    ip.add_argument("prompt_id")
    ip.add_argument("--version", default=None, help="Defaults to latest")
    return p


def main(registry: PromptRegistry, argv: list[str] | None = None) -> int:
    args = build_parser(registry).parse_args(argv)
    if args.cmd == "list":
        print(json.dumps(registry.summary(), indent=2, sort_keys=True))
        return 0
    try:
        tmpl = registry.get(args.prompt_id, args.version)
    except UnknownPromptError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(
        json.dumps(
            {
                **tmpl.usage_record(),
                "role": tmpl.role_binding,
                "required_variables": list(tmpl.required_variables),
                "expected_output_schema": tmpl.expected_output_schema,
                "description": tmpl.description,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0
