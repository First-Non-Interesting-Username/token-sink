"""Tests for the offline model benchmark."""
from __future__ import annotations

import pytest

from mavr.providers.model_benchmark import (
    SUITE_VERSION,
    BenchmarkRunner,
    all_prompts,
    prompts_for,
)
from mavr.providers.model_catalog.scores import ModelScoreStore
from mavr.schemas.routing import (
    TaskCategory,
)
from mavr.storage.database import Database, apply_migrations
from mavr.tests._fakes import MockAdapter


def test_prompts_cover_at_least_review_and_polish() -> None:
    cats = {p.category for p in all_prompts()}
    assert TaskCategory.REVIEW in cats
    assert TaskCategory.POLISH in cats


def test_prompts_for_unknown_category_is_empty() -> None:
    # All categories that don't have explicit prompt sets return [].
    assert prompts_for(TaskCategory.IMPACT) == []


@pytest.mark.asyncio
async def test_benchmark_records_results_and_updates_scores(tmp_path) -> None:
    db = Database(tmp_path / "phase4.db")
    await apply_migrations(db, "up")
    scores = ModelScoreStore(db)
    adapter = MockAdapter()
    targets: list[tuple[str, str, object]] = [
        (entry.provider_id, entry.model_key, adapter.chat)
        for entry in adapter.models()
    ]
    runner = BenchmarkRunner(db, scores)
    run_id = await runner.run(targets, actor_kind="human", actor_id="tester")
    rows = await db.fetchall(
        "SELECT passed, score, category FROM benchmark_results WHERE run_id = ?",
        (run_id,),
    )
    assert rows
    # the mock's default content includes the tokens the prompts expect
    assert any(bool(r["passed"]) for r in rows)
    # score store is updated
    score_rows = await db.fetchall("SELECT provider_id, model_key, score FROM model_scores")
    assert score_rows


@pytest.mark.asyncio
async def test_benchmark_handles_adapter_error(tmp_path) -> None:
    db = Database(tmp_path / "phase4.db")
    await apply_migrations(db, "up")
    scores = ModelScoreStore(db)
    adapter = MockAdapter(fail_on={"mock-review", "mock-discovery", "mock-polish"})

    async def _explode(model_key, request):  # type: ignore[no-redef]
        raise RuntimeError("boom")

    targets = [
        (entry.provider_id, entry.model_key, _explode)
        for entry in adapter.models()
    ]
    runner = BenchmarkRunner(db, scores)
    run_id = await runner.run(targets, actor_kind="system", actor_id="t")
    rows = await db.fetchall(
        "SELECT passed, error FROM benchmark_results WHERE run_id = ?", (run_id,)
    )
    assert rows
    assert all(not bool(r["passed"]) for r in rows)
    assert any("boom" in (r["error"] or "") for r in rows)


@pytest.mark.asyncio
async def test_benchmark_suite_version_persisted(tmp_path) -> None:
    db = Database(tmp_path / "phase4.db")
    await apply_migrations(db, "up")
    scores = ModelScoreStore(db)
    runner = BenchmarkRunner(db, scores)
    adapter = MockAdapter()
    targets = [
        (entry.provider_id, entry.model_key, adapter.chat)
        for entry in adapter.models()
    ]
    run_id = await runner.run(targets, actor_kind="system", actor_id="t")
    row = await db.fetchone(
        "SELECT suite_version, summary FROM benchmark_runs WHERE id = ?", (run_id,)
    )
    assert row["suite_version"] == SUITE_VERSION
    assert row["summary"]
