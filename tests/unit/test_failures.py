"""Unit tests for the §18 failure-handling matrix (issue #25)."""

from orchestrator.failures import (
    RECOVERY_PATHS,
    TRANSIENT_CLASSES,
    DeadLetterQueue,
    FailureClass,
    FailureRecord,
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


def _flaky(times: int, exc=RuntimeError):
    calls = {"n": 0}

    def fn():
        if calls["n"] < times:
            calls["n"] += 1
            raise exc("boom")
        return "ok"

    return fn, calls


# --- classification ------------------------------------------------------


def test_all_plan_failure_classes_have_recovery_paths():
    # every §18 class maps to a documented recovery path
    for cls in FailureClass:
        assert cls in RECOVERY_PATHS


def test_transient_classes_are_subset_with_retry_policies():
    from orchestrator.failures import DEFAULT_RETRY_POLICIES

    assert TRANSIENT_CLASSES <= set(FailureClass)
    # every retryable class has a default policy; non-retryable ones do not
    assert set(DEFAULT_RETRY_POLICIES) == TRANSIENT_CLASSES


def test_classify_known_exceptions():
    assert classify(FakeTimeout()) is FailureClass.AGENT_TIMEOUT
    assert classify(TooManyRequestsError()) is FailureClass.PROVIDER_RATE_LIMIT
    assert classify(QuotaError()) is FailureClass.QUOTA_EXHAUSTED
    assert classify(ConnectionResetError()) is FailureClass.PROVIDER_OUTAGE


def test_classify_unknown_is_conservative_non_transient():
    cls = classify(RuntimeError("mystery"))
    assert cls not in TRANSIENT_CLASSES


# --- retry behavior ------------------------------------------------------


def test_success_first_try_no_sleep():
    fn, calls = _flaky(0)
    outcome = with_retry(fn, FailureClass.PROVIDER_OUTAGE)
    assert outcome.value == "ok" and not outcome.exhausted
    assert outcome.attempts == 1


def test_transient_retries_then_succeeds():
    fn, _ = _flaky(2)
    sleeps = []
    outcome = with_retry(fn, FailureClass.PROVIDER_OUTAGE, sleep=sleeps.append)
    assert outcome.value == "ok"
    assert outcome.attempts == 3  # 2 failures + success within max_attempts=3
    assert len(sleeps) == 2  # backoff between attempts


def test_exhaustion_records_failures_and_flags():
    fn, _ = _flaky(99)
    records = []
    outcome = with_retry(
        fn,
        FailureClass.AGENT_TIMEOUT,
        on_failure=lambda r, a: records.append((r, a)),
        sleep=lambda s: None,
    )
    assert outcome.exhausted and outcome.attempts == 2
    assert len(records) == 2  # every failed attempt recorded
    assert all(isinstance(r, FailureRecord) for r, _ in records)


def test_non_transient_class_never_retries():
    fn, _ = _flaky(99)
    sleeps = []
    outcome = with_retry(fn, FailureClass.SCOPE_POLICY_REJECTION, sleep=sleeps.append)
    assert outcome.exhausted
    assert outcome.attempts == 1  # exactly-once: policy rejections never retried
    assert sleeps == []


def test_rate_limit_backoff_grows_and_caps():
    pol = RetryPolicy(max_attempts=10, base_delay_s=2.0, max_delay_s=60.0, jitter=False)
    delays = [pol.delay_for(a) for a in range(1, 8)]
    assert delays[0] == 2.0
    assert delays[1] == 4.0
    assert all(d <= 60.0 for d in delays)  # cap honored (no thundering herd)


def test_custom_policy_overrides_default():
    fn, _ = _flaky(5)
    pol = RetryPolicy(max_attempts=7, base_delay_s=0.0, max_delay_s=0.0)
    outcome = with_retry(fn, FailureClass.UI_DISCONNECT, policy=pol, sleep=lambda s: None)
    assert outcome.value == "ok"


def test_exception_inside_fn_does_not_propagate():
    def boom():
        raise ValueError("x")

    outcome = with_retry(boom, FailureClass.DATABASE_TRANSIENT)
    assert outcome.exhausted and outcome.last_failure is not None
    assert "ValueError" in outcome.last_failure.message


# --- dead-letter queue ---------------------------------------------------


def test_dead_letter_roundtrip():
    q = DeadLetterQueue()
    rec = FailureRecord(component="router", message="unroutable")
    payload = {"task": "t-1"}
    q.put(rec, payload)
    assert len(q) == 1
    items = q.drain()
    assert items[0][1] == payload
    assert len(q) == 0  # drained
