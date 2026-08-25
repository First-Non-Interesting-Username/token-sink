#!/usr/bin/env python3
"""CI check: fail if secret-shaped strings land in the repo (issue #29).

Scans tracked files for provider API-key shapes and obvious credential
assignments. Example/placeholder values (sk-example-..., changeme) are
allowed — the point is catching *real-looking* secrets.
"""

import re
import subprocess
import sys

# Real-looking key/token shapes. Placeholders use "example"/"changeme" and
# are filtered below.
PATTERNS = [
    ("openai_key", re.compile(r"sk-[A-Za-z0-9_-]{20,}")),
    ("anthropic_key", re.compile(r"sk-ant-[A-Za-z0-9_-]{20,}")),
    ("github_token", re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}")),
    ("aws_access_key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("slack_token", re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}")),
    ("private_key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
]

PLACEHOLDER_HINT = re.compile(r"(?i)example|sample|dummy|placeholder|changeme|xxxx")


def tracked_files():
    out = subprocess.run(["git", "ls-files"], capture_output=True, text=True, check=True)
    return out.stdout.splitlines()


def scan() -> int:
    hits = 0
    for path in tracked_files():
        try:
            text = open(path, encoding="utf-8", errors="replace").read()
        except OSError:
            continue
        for kind, pattern in PATTERNS:
            for m in pattern.finditer(text):
                # context around the hit decides placeholder vs real
                window = text[max(0, m.start() - 60) : m.end() + 60]
                if PLACEHOLDER_HINT.search(window):
                    continue
                print(f"POSSIBLE SECRET ({kind}) in {path}: {m.group(0)[:12]}…")
                hits += 1
    if hits:
        print(f"\n{hits} potential secret(s) found. Do not commit real credentials.")
        return 1
    print("No secret-shaped strings found in tracked files.")
    return 0


if __name__ == "__main__":
    sys.exit(scan())
