"""Command-line entrypoints (init, doctor, serve) and campaign/provider/finding/report
commands (PLAN §17).
"""

from __future__ import annotations

import argparse
import sys

from cli.campaign_wizard import run_wizard
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

    campaign = sub.add_parser("campaign", help="campaign management commands (issue #171)")
    camp_sub = campaign.add_subparsers(dest="campaign_command", required=True)
    create = camp_sub.add_parser(
        "create", help="guided interactive campaign creation with live scope validation"
    )
    create.add_argument(
        "--print-only",
        action="store_true",
        help="print the manifest JSON instead of only reporting success",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "doctor":
        report = run_doctor(config_path=args.config, skip_network=args.skip_network)
        print(report.to_json() if args.json else report.to_human())
        return report.exit_code
    if args.command == "campaign" and args.campaign_command == "create":
        try:
            manifest = run_wizard()
        except KeyboardInterrupt:
            print("\naborted")
            return 130
        except Exception as exc:  # WizardError: invalid draft can never be saved
            print(f"error: {exc}")
            return 1
        if args.print_only:
            import json

            print(json.dumps(manifest, indent=2))
        else:
            print(f"campaign manifest created: {manifest['campaign_uuid']}")
        return 0
    return 2  # unreachable with required=True subparsers; defensive


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
