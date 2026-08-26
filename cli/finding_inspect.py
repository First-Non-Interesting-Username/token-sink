"""`finding inspect` CLI: version listing + diff rendering (issue #291).

Exposes the VersionStore read-model on the command line so a reviewer can
answer "what changed since vN and who changed it" without the UI:

    finding inspect --uuid <finding-uuid> --versions
    finding inspect --uuid <finding-uuid> --diff 2 5

Pure read-only surface over :mod:`findings.version_store`; no mutation,
no network, no secrets.
"""

from __future__ import annotations

import argparse
import json

from findings.lifecycle import RecordStore
from findings.version_store import VersionStore, format_diff_report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="finding inspect", description="Inspect finding versions and diffs"
    )
    parser.add_argument("--uuid", required=True, help="finding UUID to inspect")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--versions", action="store_true", help="list all versions")
    mode.add_argument("--diff", nargs=2, metavar=("FROM", "TO"), help="diff two versions")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    return parser


def run_cli(argv: list[str], store: RecordStore, out=print) -> int:
    """Run the inspector against *store*. Output via injectable *out*."""
    args = build_parser().parse_args(argv)
    vs = VersionStore(store)

    if args.versions:
        rows = vs.versions(args.uuid)
        if args.json:
            out(json.dumps(rows, indent=2))
        else:
            for r in rows:
                out(
                    f"v{r['version']}  {r['timestamp']}  {r['author']:<20} "
                    f"{r['state']:<22} {r['reason']}"
                )
        return 0

    from_v, to_v = (int(x) for x in args.diff)
    result = vs.diff(args.uuid, from_v, to_v)
    if args.json:
        out(json.dumps(result, indent=2))
    else:
        out(format_diff_report(result))
    return 0
