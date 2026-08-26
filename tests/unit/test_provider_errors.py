"""Table-driven tests for the provider-error taxonomy (issue #176)."""

from __future__ import annotations

import pytest

from providers.errors import (
    DEFAULT_RETRY_HINTS,
    OPENAI_COMPATIBLE_MAPPING,
    BackoffClass,
    ErrorMapping,
    ProviderErrorClass,
    make_streaming_failure,
)

# Every canonical class must have retry metadata — #91/#83 consume this table.
ALL_CLASSES = set(ProviderErrorClass)


def test_every_canonical_class_has_retry_hint():
    assert ALL_CLASSES - set(DEFAULT_RETRY_HINTS) == set()
    for cls, hint in DEFAULT_RETRY_HINTS.items():
        if not hint.retryable:
            assert hint.backoff is BackoffClass.NONE
        if cls is ProviderErrorClass.RATE_LIMITED:
            assert hint.backoff is BackoffClass.HONOR_RETRY_AFTER
    # Fail safe: unknown errors are NOT auto-retried.
    assert DEFAULT_RETRY_HINTS[ProviderErrorClass.UNKNOWN].retryable is False


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        (401, ProviderErrorClass.AUTH_INVALID),
        (403, ProviderErrorClass.AUTH_INVALID),
        (404, ProviderErrorClass.MODEL_NOT_FOUND),
        (429, ProviderErrorClass.RATE_LIMITED),
        (503, ProviderErrorClass.PROVIDER_UNAVAILABLE),
        (504, ProviderErrorClass.TIMEOUT),
    ],
)
def test_openai_compatible_status_table(status, expected):
    assert OPENAI_COMPATIBLE_MAPPING.classify_status(status) is expected


def test_unmapped_status_lands_in_unknown_with_payload():
    err = OPENAI_COMPATIBLE_MAPPING.build(
        status=599, message="weird gateway", raw_payload='{"err":"x"}'
    )
    assert err.error_class is ProviderErrorClass.UNKNOWN
    # Never silently misclassified: raw payload preserved for diagnosis.
    assert err.raw_payload == '{"err":"x"}'
    assert err.hint.retryable is False


def test_exception_mapping_by_type_name():
    class RateLimitError(Exception):
        pass

    class SomeWeirdSDKError(Exception):
        pass

    m = OPENAI_COMPATIBLE_MAPPING
    assert m.classify_exception(RateLimitError()) is ProviderErrorClass.RATE_LIMITED
    assert m.classify_exception(SomeWeirdSDKError()) is ProviderErrorClass.UNKNOWN
    assert m.classify_exception("APITimeoutError") is ProviderErrorClass.TIMEOUT


def test_adapter_override_of_shared_baseline():
    """Adapters extend the baseline where their provider deviates."""
    kilo = ErrorMapping(
        adapter="kilo",
        status_map={
            **OPENAI_COMPATIBLE_MAPPING.status_map,
            402: ProviderErrorClass.QUOTA_EXHAUSTED,
        },
        exception_map=OPENAI_COMPATIBLE_MAPPING.exception_map,
    )
    assert kilo.classify_status(402) is ProviderErrorClass.QUOTA_EXHAUSTED
    # Baseline untouched — tables are copied per adapter.
    with pytest.raises(KeyError):
        _ = OPENAI_COMPATIBLE_MAPPING.status_map[402]


def test_streaming_failure_distinct_from_preflight_and_preserves_partial():
    preflight = OPENAI_COMPATIBLE_MAPPING.build(status=503, message="down")
    stream = make_streaming_failure(
        "kilo", partial_output="The vuln is in", cause=ProviderErrorClass.TIMEOUT
    )
    # Distinct classification:
    assert not preflight.streaming_failure and preflight.partial_output is None
    assert stream.streaming_failure and stream.partial_output == "The vuln is in"
    # Retryable mid-stream timeout still carries its hint.
    assert stream.hint.retryable is True
    # Serialization keeps everything downstream needs (#156 metrics feed).
    d = stream.to_dict()
    assert d["error_class"] == "timeout" and d["streaming_failure"] is True


def test_error_is_raiseable_and_carries_id():
    err = OPENAI_COMPATIBLE_MAPPING.build(status=429, message="slow down", raw_payload="rl")
    assert isinstance(err, Exception)
    assert "[rate_limited]" in str(err)
    assert err.error_id.startswith("perr_")
