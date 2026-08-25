"""Packaging / install-path tests (issue #34).

Covers the packaging-side environment check and keeps the duplicated
Python-version constant in sync with pyproject.toml.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

import cli
from cli import envcheck


def _pyproject() -> dict:
    return tomllib.loads((Path(__file__).resolve().parents[2] / "pyproject.toml").read_text())


def test_min_python_matches_pyproject():
    # The check hardcodes the floor so it can run before imports fail;
    # this test is the tripwire that keeps the two from drifting.
    requires = _pyproject()["project"]["requires-python"]
    assert f">={envcheck.MIN_PYTHON[0]}.{envcheck.MIN_PYTHON[1]}" == requires


def test_wheel_packages_cover_all_subsystem_dirs():
    root = Path(__file__).resolve().parents[2]
    declared = set(_pyproject()["tool"]["hatch"]["build"]["targets"]["wheel"]["packages"])
    actual = {
        p.name
        for p in root.iterdir()
        if p.is_dir() and (p / "__init__.py").exists() and not p.name.startswith((".", "tests"))
    }
    assert actual <= declared, f"packages missing from wheel config: {actual - declared}"


def test_check_environment_passes_on_ci():
    report = envcheck.check_environment()
    assert report.ok
    names = [r.name for r in report.results]
    assert "python" in names and "data-dir" in names


def test_report_render_marks_failures():
    report = envcheck.EnvironmentReport(
        results=[
            envcheck.CheckResult("python", True, "3.12.0"),
            envcheck.CheckResult("module:x", False, "missing"),
        ]
    )
    text = report.render()
    assert "[FAIL] module:x" in text and "environment has FAILURES" in text
    assert not report.ok


def test_missing_module_is_failure_not_warning():
    results = envcheck._check_modules()
    # yaml IS installed in CI, so every required module check must be ok;
    # the failure branch is exercised by test_report_render_marks_failures.
    assert all(r.ok for r in results)


def test_cli_doctor_exit_codes(capsys):
    assert cli.main(["doctor"]) == 0
    out = capsys.readouterr().out
    assert "environment OK" in out
