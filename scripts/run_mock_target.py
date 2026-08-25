#!/usr/bin/env python3
"""CLI equivalent of `make fixtures` (issue #95): start the mock target on a
random loopback port and print the base URL. Ctrl-C stops it."""

import sys

sys.path.insert(0, ".")

from evaluation.mock_target.fixtures import FIXTURES  # noqa: E402
from evaluation.mock_target.server import start_server  # noqa: E402


def main() -> int:
    server, base_url = start_server()
    print(f"mock-target listening on {base_url}")
    print("fixtures:")
    for f in FIXTURES.values():
        print(f"  {f.fixture_id:<16} {f.vuln_class:<14} {f.path}")
    print("Ctrl-C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.shutdown()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
