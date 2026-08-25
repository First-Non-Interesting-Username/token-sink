"""Command-line entrypoints (init, doctor, serve) and campaign/provider/finding/report
commands (PLAN §17).
"""

from __future__ import annotations

import argparse
import sys

from cli.doctor import run_doctor


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="token-sink", description="token-sink CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    doctor = sub.add_parser("doctor", help="environment/config diagnostics (issue #93)")
    doctor.add_argument("--config", default=None, help="path to config file")
    doctor.add_argument("--json", action="store_true", help="machine-readable JSON output")
    doctor.add_argument(
        "--skip-network",
        action="store_true",
        help="skip provider endpoint reachability probes (offline environments)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "doctor":
        report = run_doctor(config_path=args.config, skip_network=args.skip_network)
        print(report.to_json() if args.json else report.to_human())
        return report.exit_code
    return 2  # unreachable with required=True subparsers; defensive


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
