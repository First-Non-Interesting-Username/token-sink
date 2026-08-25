"""Packaging-side environment check for install/launch (issue #34).

This is deliberately NOT the full ``system doctor`` diagnostics command
(PLAN §17 — delivered separately via issue #93): it is the small
prerequisite check that runs at install/launch time so a broken
environment fails fast with actionable output instead of an obscure
import error deep in a campaign.

Checks (cheap → expensive, per AGENTS.md comment conventions):
- Python version meets ``requires-python`` from pyproject.
- Runtime dependencies import cleanly (yaml).
- External tools the search/extraction subsystem shells out to (curl)
  are present. curl is optional at launch; missing it is a warning,
  not a failure, because not every subsystem needs it yet.
- The data directory is writable (SQLite + artifact store live there).
"""

from __future__ import annotations

import shutil
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

# Mirrors [project] requires-python = ">=3.11" in pyproject.toml.
# Kept in sync manually; test_packaging.py asserts the two agree.
MIN_PYTHON = (3, 11)

# Modules that must be importable at launch. Only hard runtime deps belong
# here — dev-only tools (pytest, ruff) are intentionally excluded.
REQUIRED_MODULES = ("yaml",)

# External binaries some subsystems shell out to. Warning-only: the app can
# start without them and the affected features degrade with a clear error.
OPTIONAL_BINARIES = ("curl",)


@dataclass
class CheckResult:
    name: str
    ok: bool
    detail: str = ""


@dataclass
class EnvironmentReport:
    results: list[CheckResult] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        # Warnings (optional binaries) don't block launch; failures do.
        return all(r.ok for r in self.results)

    @property
    def warnings(self) -> list[CheckResult]:
        return [r for r in self.results if r.ok and r.detail]

    def render(self) -> str:
        lines = []
        for r in self.results:
            mark = "OK  " if r.ok else "FAIL"
            line = f"[{mark}] {r.name}"
            if r.detail:
                line += f" — {r.detail}"
            lines.append(line)
        lines.append("environment OK" if self.ok else "environment has FAILURES")
        return "\n".join(lines)


def _check_python() -> CheckResult:
    v = sys.version_info
    ok = (v.major, v.minor) >= MIN_PYTHON
    return CheckResult(
        "python",
        ok,
        f"{v.major}.{v.minor}.{v.micro} (requires >={MIN_PYTHON[0]}.{MIN_PYTHON[1]})",
    )


def _check_modules() -> list[CheckResult]:
    out = []
    for mod in REQUIRED_MODULES:
        try:
            m = __import__(mod)  # noqa: F401 — import success is the point
        except ImportError as e:
            out.append(CheckResult(f"module:{mod}", False, f"missing ({e}); reinstall the package"))
        else:
            out.append(CheckResult(f"module:{mod}", True, getattr(m, "__version__", "")))
    return out


def _check_binaries() -> list[CheckResult]:
    out = []
    for bin_name in OPTIONAL_BINARIES:
        path = shutil.which(bin_name)
        if path:
            out.append(CheckResult(f"binary:{bin_name}", True, path))
        else:
            # OK but flagged — see OPTIONAL_BINARIES docstring.
            detail = "not found (optional; some features degraded)"
            out.append(CheckResult(f"binary:{bin_name}", True, detail))
    return out


def _check_data_dir(data_dir: Path | None) -> CheckResult:
    target = data_dir or Path.home() / ".local" / "share" / "token-sink"
    try:
        target.mkdir(parents=True, exist_ok=True)
        # Actually write+delete: mkdir on an existing dir succeeds even when
        # unwritable, which would defeat the check.
        with tempfile.NamedTemporaryFile(dir=target, prefix=".envcheck-"):
            pass
    except OSError as e:
        return CheckResult("data-dir", False, f"{target}: {e}")
    return CheckResult("data-dir", True, str(target))


def check_environment(data_dir: Path | None = None) -> EnvironmentReport:
    """Run all prerequisite checks and return the collected report."""
    report = EnvironmentReport()
    report.results.append(_check_python())
    report.results.extend(_check_modules())
    report.results.extend(_check_binaries())
    report.results.append(_check_data_dir(data_dir))
    return report
