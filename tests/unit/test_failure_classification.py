"""Table-driven unit tests for failure classification + retry policies (issue #91)."""

from __future__ import annotations

import pytest

from orchestrator.failures import (
    DEFAULT_RETRY_POLICIES,
    RECOVERY_PATHS,
    TRANSIENT_CLASSES,
    DeadLetterQueue,
    FailureClass,
    FailureLogger,
    FailureRecord,
    ModelQualityError,
    RetryBudget,
    RetryPolicy,
    classify,
    with_retry,
)


class FakeTimeout(Exception):
    pass


class TooManyRequestsError(Exception):
    pass


class QuotaError(Exception):
    pass


class WeirdVendorError(Exception):
    """Simulates a vendor-specific error an adapter must teach the classifier."""


# --- classification table (§19.1: table-driven over fixture-style inputs) --

CLASSIFICATION_TABLE = [
    # (exception, expected class)
    (FakeTimeout("read timed out"), FailureClass.AGENT_TIMEOUT),
    (TimeoutError(), FailureClass.AGENT_TIMEOUT),
    (TooManyRequestsError("429"), FailureClass.PROVIDER_RATE_LIMIT),
    (QuotaError("quota exceeded"), FailureClass.QUOTA_EXHAUSTED),
    (ConnectionError("refused"), FailureClass.PROVIDER_OUTAGE),
    (OSError("network down"), FailureClass.PROVIDER_OUTAGE),
    (ValueError("invalid JSON in response"), FailureClass.MALFORMED_OUTPUT),
    # Unknown → conservative non-transient, never blind-retried:
    (WeirdVendorError("???"), FailureClass.MALFORMED_OUTPUT),
    (ModelQualityError("valid JSON, wrong facts"), FailureClass.MODEL_QUALITY),
]


@pytest.mark.parametrize(("exc", "expected"), CLASSIFICATION_TABLE)
def test_classification_table(exc, expected) -> None:
    assert classify(exc) is expected


def test_data_driven_rules_take_precedence() -> None:
    """Provider adapters contribute error-normalization rules (§8.1)."""
    exc = WeirdVendorError("err_code=VENDOR_SATURATED")
    rules = [("vendor_saturated", FailureClass.PROVIDER_OUTAGE)]
    assert classify(exc, rules=rules) is FailureClass.PROVIDER_OUTAGE
    # Without the rule it falls to the conservative default.
    assert classify(exc) is FailureClass.MALFORMED_OUTPUT


def test_rules_match_message_not_just_type() -> None:
    rules = [("context window full", FailureClass.QUOTA_EXHAUSTED)]
    assert classify(RuntimeError("Context Window Full"), rules=rules) is (
        FailureClass.QUOTA_EXHAUSTED
    )


def test_model_quality_has_no_retry_policy_and_negative_signal_path() -> None:
    """MODEL_QUALITY never retries same-model; recovery path feeds score system."""
    assert FailureClass.MODEL_QUALITY not in TRANSIENT_CLASSES
    assert FailureClass.MODEL_QUALITY in RECOVERY_PATHS
    assert RECOVERY_PATHS[FailureClass.MODEL_QUALITY] == ("negative_score_signal_then_reroute")
    assert FailureClass.MODEL_QUALITY not in DEFAULT_RETRY_POLICIES


# --- per-class policy behavior --------------------------------------------

POLICY_TABLE = [
    # (class, transient?, has default policy?)
    (FailureClass.PROVIDER_OUTAGE, True, True),
    (FailureClass.PROVIDER_RATE_LIMIT, True, True),
    (FailureClass.AGENT_TIMEOUT, True, True),
    (FailureClass.DATABASE_TRANSIENT, True, True),
    (FailureClass.UI_DISCONNECT, True, True),
    (FailureClass.MODEL_QUALITY, False, False),
    (FailureClass.SCOPE_POLICY_REJECTION, False, False),
    (FailureClass.POC_SAFETY_FAILURE, False, False),
]


@pytest.mark.parametrize(("failure_class", "transient", "has_policy"), POLICY_TABLE)
def test_per_class_policies(failure_class, transient, has_policy) -> None:
    assert (failure_class in TRANSIENT_CLASSES) is transient
    assert (failure_class in DEFAULT_RETRY_POLICIES) is has_policy


def test_policy_rejection_is_never_retried() -> None:
    calls = {"n": 0}

    def fn():
        calls["n"] += 1
        raise ValueError("out of scope")

    outcome = with_retry(fn, FailureClass.SCOPE_POLICY_REJECTION, sleep=lambda s: None)
    assert calls["n"] == 1  # executed once, no retry
    assert outcome.exhausted
    assert outcome.last_failure is not None
    assert outcome.last_failure.failure_class == FailureClass.SCOPE_POLICY_REJECTION


# --- backoff with jitter ----------------------------------------------------


def test_backoff_is_exponential_and_capped() -> None:
    policy = RetryPolicy(max_attempts=10, base_delay_s=1.0, max_delay_s=8.0, jitter=False)
    assert [policy.delay_for(a) for a in range(1, 6)] == [1.0, 2.0, 4.0, 8.0, 8.0]


def test_jitter_stays_within_half_of_base_delay() -> None:
    policy = RetryPolicy(5, 2.0, 60.0, jitter=True)
    for _ in range(50):
        d = policy.delay_for(1)
        assert 1.0 <= d <= 2.0  # uniform factor in [0.5, 1.0)


def test_jitter_accepts_injected_rng_for_determinism() -> None:
    policy = RetryPolicy(3, 2.0, 60.0, jitter=True)
    # rng returns r in [0,1); factor is 0.5 + r*0.5 → delay in [1.0, 2.0).
    assert policy.delay_for(1, rng=lambda: 0.0) == pytest.approx(1.0)
    assert policy.delay_for(1, rng=lambda: 1.0) == pytest.approx(2.0)


# --- retry budgets -----------------------------------------------------------


def test_task_budget_exhaustion_stops_retries() -> None:
    budget = RetryBudget(task_retries=2, campaign_retries=100)
    budget.spend("t1")
    budget.spend("t1")
    assert not budget.can_retry("t1")
    assert budget.can_retry("t2")  # other tasks unaffected


def test_campaign_budget_exhaustion_blocks_all_tasks() -> None:
    budget = RetryBudget(task_retries=10, campaigns={"c1": 3})
    for i in range(3):
        budget.spend(f"task{i}", campaign_id="c1")
    assert budget.can_retry("fresh-task", campaign_id="c1") is False
    # "default" has its own configured budget and is unaffected.
    assert budget.can_retry("any-task", campaign_id="default") is True


# --- observability of decisions ----------------------------------------------


def test_failure_logger_records_decisions() -> None:
    logger = FailureLogger()
    logger.log("t1", FailureClass.PROVIDER_OUTAGE, "retry", "attempt 1/3")
    logger.log("t1", FailureClass.MODEL_QUALITY, "reroute", "negative quality signal")
    assert len(logger.entries) == 2
    entry = logger.entries[1]
    assert entry["decision"] == "reroute"
    assert entry["failure_class"] == "model_quality"
    assert "quality" in entry["reason"]


def test_dead_letter_integration_after_budget_exhaustion() -> None:
    dlq = DeadLetterQueue()
    budget = RetryBudget(task_retries=1)
    record = FailureRecord(failure_class=FailureClass.PROVIDER_OUTAGE)

    if budget.can_retry("t9"):
        budget.spend("t9")
    if not budget.can_retry("t9"):
        dlq.put(record, {"task": "t9"})

    assert len(dlq) == 1
