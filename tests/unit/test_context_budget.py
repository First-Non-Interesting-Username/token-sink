"""Unit tests for routers/context_budget.py (issue #170, PLAN §7)."""

import pytest

from routers.context_budget import (
    BudgetCheck,
    ContextBudgetError,
    check_budget,
    estimate_tokens,
    plan_for_model,
    plan_with_catalog,
)


class FakeEntry:
    """Minimal duck-typed CatalogEntry."""

    def __init__(self, key="prov/model", context_window=32_000, max_output_tokens=4_096):
        self.key = key
        self.context_window = context_window
        self.max_output_tokens = max_output_tokens


# -- estimation ---------------------------------------------------------------


def test_estimate_tokens_basic():
    assert estimate_tokens("a" * 400) == 100
    assert estimate_tokens("") == 0


def test_estimate_rejects_bad_ratio():
    with pytest.raises(ValueError):
        estimate_tokens("x", chars_per_token=0)


# -- budget check ---------------------------------------------------------------


def test_fits_when_under_window():
    out = check_budget("a" * 400, context_window=1_000, reserved_output=200)
    assert isinstance(out, BudgetCheck)
    assert out.fits


def test_fails_when_input_plus_output_exceeds():
    out = check_budget("a" * 10_000, context_window=1_000, reserved_output=500)
    assert not out.fits
    assert "exceeds" in out.reason


def test_unknown_window_never_fits():
    out = check_budget("tiny", context_window=0, reserved_output=10)
    assert not out.fits and "unknown" in out.reason


def test_reserved_output_must_be_below_window():
    out = check_budget("x", context_window=100, reserved_output=100)
    assert not out.fits


# -- splitting ---------------------------------------------------------------


def test_no_split_when_it_already_fits():
    plan = plan_for_model("short task", 8_000, reserved_output=1_000)
    assert plan.chunks == ("short task",)
    assert len(plan.chunks) == 1


def test_oversized_task_splits_into_ordered_chunks():
    text = "x" * 40_000
    plan = plan_for_model(text, context_window=8_000, reserved_output=2_000)
    assert len(plan.chunks) > 1
    # order preserved: rejoining (minus markers) reconstructs the input
    joined = "".join(
        c.replace("[continued] ", "", 1) if i else c for i, c in enumerate(plan.chunks)
    )
    assert joined == text


def test_every_chunk_fits_after_split():
    text = "y" * 50_000
    window, reserved = 4_000, 800
    plan = plan_for_model(text, window, reserved)
    for chunk in plan.chunks:
        est = estimate_tokens(chunk)
        assert est + reserved <= window, f"chunk over budget: {est}"


def test_unusable_window_raises():
    with pytest.raises(ContextBudgetError):
        plan_for_model("some task", context_window=300, reserved_output=290, min_chunk_chars=200)


# -- catalog integration ------------------------------------------------------


def test_plan_with_catalog_reserves_output_share():
    entry = FakeEntry(context_window=10_000, max_output_tokens=4_096)
    plan = plan_with_catalog(entry, "z" * 100_000)
    assert plan.reserved_output_tokens == 2_500  # 25% of window
    assert plan.model_key == "prov/model"
    assert len(plan.chunks) > 1


def test_plan_with_catalog_caps_reservation_at_max_output():
    entry = FakeEntry(context_window=10_000, max_output_tokens=1_000)
    plan = plan_with_catalog(entry, "fits")
    assert plan.reserved_output_tokens == 1_000


def test_plan_with_catalog_unknown_window_raises():
    with pytest.raises(ContextBudgetError):
        plan_with_catalog(FakeEntry(context_window=0), "task")
