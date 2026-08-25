"""CLI entry point. Phase 1 exposes only `token-sink check-config`; the full
init/doctor/serve surface is PLAN.md §17 and lands with its own issue."""

import argparse
import sys

from config_loader import ConfigValidationError, load


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="token-sink")
    sub = parser.add_subparsers(dest="command", required=True)

    p_check = sub.add_parser("check-config", help="Validate a config file and report ALL problems")
    p_check.add_argument("path", help="Path to a .yaml/.yml or .toml config file")

    args = parser.parse_args(argv)
    if args.command == "check-config":
        try:
            load(args.path)
        except ConfigValidationError as exc:
            print(f"configuration invalid:\n{exc}", file=sys.stderr)
            return 1
        except Exception as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        print("configuration OK")
        return 0
    return 2


if __name__ == "__main__":
    sys.exit(main())
