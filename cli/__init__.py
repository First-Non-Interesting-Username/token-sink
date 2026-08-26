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
    pt = sub.add_parser("provider", help="provider operations (PLAN §17)")
    psub = pt.add_subparsers(dest="provider_command", required=True)
    ptest = psub.add_parser("test", help="probe a custom endpoint's connectivity + models")
    ptest.add_argument("id", help="custom endpoint name from config custom_endpoints")
    ptest.add_argument("--config", default="config.yaml", help="path to config file")

    args = parser.parse_args(argv)
    if args.command == "doctor":
        report = envcheck.check_environment()
        print(report.render())
        return 0 if report.ok else 1
    if args.command == "provider":
        # Deferred import: keeps `token-sink doctor` startup light.
        from cli import provider_test
        from config.loader import load_config

        cfg = load_config(args.config)
        return provider_test.run_provider_test(cfg, args.id)
    return 2  # unreachable: argparse enforces the subcommand


if __name__ == "__main__":
    sys.exit(main())
