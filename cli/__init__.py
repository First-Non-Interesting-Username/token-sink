"""Command-line entrypoints (init, doctor, serve) and campaign/provider/finding/report
commands (PLAN §17).

Currently exposes the packaging-side entrypoint (issue #34): ``token-sink
doctor`` runs the lightweight install/launch environment check from
``cli.envcheck``. The full ``system doctor`` diagnostics command is a
separate deliverable (PLAN §17, issue #93).
"""

from __future__ import annotations

import argparse
import sys

from cli import envcheck


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="token-sink", description="token-sink CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("doctor", help="check install/runtime prerequisites")

    args = parser.parse_args(argv)
    if args.command == "doctor":
        report = envcheck.check_environment()
        print(report.render())
        return 0 if report.ok else 1
    return 2  # unreachable: argparse enforces the subcommand


if __name__ == "__main__":
    sys.exit(main())
