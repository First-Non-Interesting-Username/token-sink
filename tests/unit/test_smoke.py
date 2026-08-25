"""Smoke test for the unit-test category.

Real unit tests land with each subsystem (PLAN §19.1). This keeps the
category wired into CI from day one so failures here mean a broken
pipeline, not a missing feature.
"""


def test_pytest_collects_and_runs():
    assert 1 + 1 == 2


def test_repo_layout_present():
    from pathlib import Path

    root = Path(__file__).resolve().parents[2]
    # Layout conventions other agents will rely on — fail loudly if moved.
    assert (root / "PLAN.md").is_file()
    assert (root / "tests" / "safety").is_dir()
    assert (root / "evaluation").is_dir()
