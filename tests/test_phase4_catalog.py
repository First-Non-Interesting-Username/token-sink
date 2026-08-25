"""Tests for the model catalog and score store."""
from __future__ import annotations

import pytest

from mavr.providers.model_catalog.bootstrap import CatalogBootstrapper
from mavr.providers.model_catalog.catalog import (
    ALL_FREE_MODEL_ENTRIES,
    GEMINI_FREE_MODELS,
    HUGGINGFACE_FREE_MODELS,
    KILO_GATEWAY_FREE_MODELS,
    OPENCODE_ZEN_FREE_MODELS,
    entries_by_provider,
)
from mavr.providers.model_catalog.scores import ModelScoreStore
from mavr.schemas.routing import ModelScore, TaskCategory
from mavr.storage.database import Database, apply_migrations


def test_catalog_only_contains_confirmed_free_models() -> None:
    for entry in ALL_FREE_MODEL_ENTRIES:
        assert entry.free is True
        assert entry.free_status == "confirmed"
        assert entry.model_key.strip()
        assert entry.provider_id.strip()


def test_catalog_has_four_providers_with_free_models() -> None:
    by_provider = entries_by_provider()
    assert set(by_provider.keys()) == {"huggingface", "gemini", "opencode_zen", "kilo_gateway"}
    assert by_provider["huggingface"] == HUGGINGFACE_FREE_MODELS
    assert by_provider["gemini"] == GEMINI_FREE_MODELS
    assert by_provider["opencode_zen"] == OPENCODE_ZEN_FREE_MODELS
    assert by_provider["kilo_gateway"] == KILO_GATEWAY_FREE_MODELS


@pytest.mark.asyncio
async def test_bootstrap_writes_providers_and_models(tmp_path) -> None:
    db = Database(tmp_path / "phase4.db")
    await apply_migrations(db, "up")
    bootstrapper = CatalogBootstrapper(db)
    n = await bootstrapper.run()
    assert n == len(ALL_FREE_MODEL_ENTRIES)
    rows = await db.fetchall("SELECT provider_id, kind FROM providers ORDER BY provider_id")
    pids = [r["provider_id"] for r in rows]
    assert pids == sorted({"huggingface", "gemini", "opencode_zen", "kilo_gateway"})


@pytest.mark.asyncio
async def test_bootstrap_is_idempotent(tmp_path) -> None:
    db = Database(tmp_path / "phase4.db")
    await apply_migrations(db, "up")
    bootstrapper = CatalogBootstrapper(db)
    n1 = await bootstrapper.run()
    n2 = await bootstrapper.run()
    assert n1 == n2 == len(ALL_FREE_MODEL_ENTRIES)
    rows = await db.fetchall("SELECT COUNT(*) AS c FROM models")
    assert rows[0]["c"] == len(ALL_FREE_MODEL_ENTRIES)


@pytest.mark.asyncio
async def test_score_store_upsert_and_query(tmp_path) -> None:
    db = Database(tmp_path / "phase4.db")
    await apply_migrations(db, "up")
    store = ModelScoreStore(db)
    score = ModelScore(
        provider_id="gemini",
        model_key="gemini-1.5-flash",
        category=TaskCategory.REVIEW,
        score=0.8,
        sample_count=4,
        confidence_low=0.5,
        confidence_high=0.95,
    )
    await store.upsert(score)
    got = await store.get("gemini", "gemini-1.5-flash", TaskCategory.REVIEW)
    assert got is not None
    assert got.score == pytest.approx(0.8)
    assert got.sample_count == 4


@pytest.mark.asyncio
async def test_score_update_from_samples_recency_weighted(tmp_path) -> None:
    db = Database(tmp_path / "phase4.db")
    await apply_migrations(db, "up")
    store = ModelScoreStore(db)
    # seed prior
    await store.upsert(
        ModelScore(
            provider_id="gemini",
            model_key="gemini-1.5-flash",
            category=TaskCategory.REVIEW,
            score=0.6,
            sample_count=10,
            confidence_low=0.4,
            confidence_high=0.8,
        )
    )
    # feed a batch of perfect samples; recency weight should pull the
    # new score toward 1.0 but not all the way (because the prior is
    # heavily weighted)
    new = await store.update_from_samples(
        "gemini",
        "gemini-1.5-flash",
        TaskCategory.REVIEW,
        [1.0, 1.0, 1.0, 1.0],
    )
    assert new.score > 0.6
    assert new.sample_count == 14
    assert 0.0 <= new.score <= 1.0


@pytest.mark.asyncio
async def test_score_for_category_returns_sorted(tmp_path) -> None:
    db = Database(tmp_path / "phase4.db")
    await apply_migrations(db, "up")
    store = ModelScoreStore(db)
    for score, key in [
        (0.3, "a"),
        (0.9, "b"),
        (0.6, "c"),
    ]:
        await store.upsert(
            ModelScore(
                provider_id="p",
                model_key=key,
                category=TaskCategory.GENERIC,
                score=score,
                sample_count=5,
                confidence_low=score - 0.1,
                confidence_high=score + 0.1,
            )
        )
    rows = await store.for_category(TaskCategory.GENERIC)
    assert [r.model_key for r in rows] == ["b", "c", "a"]
