"""Canonical provider-error taxonomy + per-adapter mapping (PLAN §8.1, §18;
issue #176).

Every provider adapter surfaces errors differently — HTTP codes, SDK
exceptions, streaming dropouts. Without a shared error model the failure
classifier (#91), circuit breakers (#83), and router fallbacks can't behave
consistently; adapter quirks would leak upward.

This module defines:

- :class:`ProviderErrorClass` — the canonical classes from issue #176.
- :class:`RetryHint` — structured retry metadata (retryable, retry-after,
  backoff class) so #91/#83 consume one interface.
- :class:`ProviderError` — canonical error with redacted raw payload attached.
  Unmapped errors land in ``UNKNOWN`` with the payload preserved — never
  silently misclassified.
- :class:`ErrorMapping` — a per-adapter mapping table as pure data
  (HTTP status / exception name → canonical class).
- :class:`StreamingFailure` — mid-stream failures classified distinctly from
  clean pre-flight rejections, preserving partial output for diagnosis.

Redaction is the caller's responsibility (the redaction pipeline lives in its
own subsystem) — this module only carries whatever it is given.
"""

from __future__ import annotations

import enum
import time
import uuid
from dataclasses import dataclass, field
from typing import Any


class ProviderErrorClass(enum.Enum):
    """Canonical provider-error classes (issue #176)."""

    AUTH_INVALID = "auth_invalid"
    QUOTA_EXHAUSTED = "quota_exhausted"
    RATE_LIMITED = "rate_limited"  # carries retry-after when available
    MODEL_NOT_FOUND = "model_not_found"
    CONTEXT_OVERFLOW = "context_overflow"
    CONTENT_FILTERED = "content_filtered"
    PROVIDER_UNAVAILABLE = "provider_unavailable"
    TIMEOUT = "timeout"
    MALFORMED_RESPONSE = "malformed_response"
    CANCELLED = "cancelled"
    UNKNOWN = "unknown"  # unmapped; raw payload attached, never misclassified


class BackoffClass(enum.Enum):
    """How retries should back off for this error."""

    NONE = "none"  # not retryable at all
    FIXED = "fixed"  # constant delay
    EXPONENTIAL = "exponential"  # doubling with jitter upstream
    HONOR_RETRY_AFTER = "honor_retry_after"  # server told us exactly when


# Retry metadata per canonical class — the single interface consumed by the
# failure classifier (#91) and circuit breakers (#83).
DEFAULT_RETRY_HINTS: dict[ProviderErrorClass, RetryHint] = {}


@dataclass(frozen=True)
class RetryHint:
    """Structured retry guidance attached to a canonical error."""

    retryable: bool
    retry_after_seconds: float | None = None  # explicit server hint
    backoff: BackoffClass = BackoffClass.NONE


def _hint(
    retryable: bool, retry_after: float | None = None, backoff: BackoffClass | None = None
) -> RetryHint:
    if backoff is None:
        backoff = (
            BackoffClass.HONOR_RETRY_AFTER
            if retry_after
            else (BackoffClass.EXPONENTIAL if retryable else BackoffClass.NONE)
        )
    return RetryHint(retryable=retryable, retry_after_seconds=retry_after, backoff=backoff)


DEFAULT_RETRY_HINTS.update(
    {
        ProviderErrorClass.AUTH_INVALID: _hint(False),
        ProviderErrorClass.QUOTA_EXHAUSTED: _hint(False),
        ProviderErrorClass.RATE_LIMITED: _hint(True, backoff=BackoffClass.HONOR_RETRY_AFTER),
        ProviderErrorClass.MODEL_NOT_FOUND: _hint(False),
        ProviderErrorClass.CONTEXT_OVERFLOW: _hint(False),
        ProviderErrorClass.CONTENT_FILTERED: _hint(False),
        ProviderErrorClass.PROVIDER_UNAVAILABLE: _hint(True),
        ProviderErrorClass.TIMEOUT: _hint(True),
        ProviderErrorClass.MALFORMED_RESPONSE: _hint(True),
        ProviderErrorClass.CANCELLED: _hint(False),
        ProviderErrorClass.UNKNOWN: _hint(False),  # fail safe: don't retry what we don't understand
    }
)


@dataclass(frozen=True)
class ProviderError(Exception):
    """Canonical provider error carrying structured retry metadata."""

    error_class: ProviderErrorClass
    message: str
    adapter: str  # which adapter produced it ("opencode_zen", "kilo", ...)
    hint: RetryHint = field(default_factory=lambda: DEFAULT_RETRY_HINTS[ProviderErrorClass.UNKNOWN])
    raw_payload: str = ""  # REDACTED raw response/exception text for diagnosis
    http_status: int | None = None
    streaming_failure: bool = False  # True = mid-stream, distinct from pre-flight
    partial_output: str | None = None  # preserved partial stream content
    occurred_at: float = field(default_factory=time.time)
    error_id: str = field(default_factory=lambda: f"perr_{uuid.uuid4().hex[:12]}")

    def __post_init__(self) -> None:
        # Exception requires a string args tuple; keep the message first so
        # logs read naturally.
        super().__init__(f"[{self.error_class.value}] {self.message}")

    def to_dict(self) -> dict[str, Any]:
        return {
            "error_id": self.error_id,
            "error_class": self.error_class.value,
            "message": self.message,
            "adapter": self.adapter,
            "retryable": self.hint.retryable,
            "retry_after_seconds": self.hint.retry_after_seconds,
            "backoff": self.hint.backoff.value,
            "raw_payload": self.raw_payload,
            "http_status": self.http_status,
            "streaming_failure": self.streaming_failure,
            "partial_output": self.partial_output,
            "occurred_at": self.occurred_at,
        }


class ErrorMapping:
    """Per-adapter mapping table: raw signals → canonical class.

    Pure data — adapters declare their provider's HTTP codes and exception
    names; unmapped signals fall through to UNKNOWN with the payload attached.
    """

    def __init__(
        self,
        adapter: str,
        status_map: dict[int, ProviderErrorClass],
        exception_map: dict[str, ProviderErrorClass],
    ) -> None:
        self.adapter = adapter
        self.status_map = dict(status_map)
        self.exception_map = dict(exception_map)

    def classify_status(self, status: int) -> ProviderErrorClass:
        return self.status_map.get(status, ProviderErrorClass.UNKNOWN)

    def classify_exception(self, exc: BaseException | str) -> ProviderErrorClass:
        """Map an exception by its type name (avoids importing SDK types)."""
        name = type(exc).__name__ if isinstance(exc, BaseException) else exc
        return self.exception_map.get(name, ProviderErrorClass.UNKNOWN)

    def build(
        self,
        *,
        error_class: ProviderErrorClass | None = None,
        status: int | None = None,
        exception: BaseException | str | None = None,
        message: str = "",
        raw_payload: str = "",
        **kwargs: Any,
    ) -> ProviderError:
        """Build a canonical ProviderError from a raw signal."""
        if error_class is None:
            if status is not None:
                error_class = self.classify_status(status)
            elif exception is not None:
                error_class = self.classify_exception(exception)
            else:
                raise ValueError("need one of error_class/status/exception")
        return ProviderError(
            error_class=error_class,
            message=message or f"{self.adapter} error",
            adapter=self.adapter,
            hint=DEFAULT_RETRY_HINTS[error_class],
            raw_payload=raw_payload,
            http_status=status,
            **kwargs,
        )


# Shared OpenAI-compatible baseline — most free gateways speak this dialect,
# so adapters start from here and override where their provider deviates.
OPENAI_COMPATIBLE_MAPPING = ErrorMapping(
    adapter="openai_compatible",
    status_map={
        401: ProviderErrorClass.AUTH_INVALID,
        403: ProviderErrorClass.AUTH_INVALID,
        404: ProviderErrorClass.MODEL_NOT_FOUND,
        408: ProviderErrorClass.TIMEOUT,
        409: ProviderErrorClass.CANCELLED,
        413: ProviderErrorClass.CONTEXT_OVERFLOW,
        422: ProviderErrorClass.CONTENT_FILTERED,
        429: ProviderErrorClass.RATE_LIMITED,
        500: ProviderErrorClass.PROVIDER_UNAVAILABLE,
        502: ProviderErrorClass.PROVIDER_UNAVAILABLE,
        503: ProviderErrorClass.PROVIDER_UNAVAILABLE,
        504: ProviderErrorClass.TIMEOUT,
    },
    exception_map={
        "AuthenticationError": ProviderErrorClass.AUTH_INVALID,
        "PermissionDeniedError": ProviderErrorClass.AUTH_INVALID,
        "NotFoundError": ProviderErrorClass.MODEL_NOT_FOUND,
        "BadRequestError": ProviderErrorClass.CONTEXT_OVERFLOW,
        "RateLimitError": ProviderErrorClass.RATE_LIMITED,
        "APIConnectionError": ProviderErrorClass.PROVIDER_UNAVAILABLE,
        "APITimeoutError": ProviderErrorClass.TIMEOUT,
        "APIError": ProviderErrorClass.MALFORMED_RESPONSE,
    },
)


def make_streaming_failure(
    adapter: str,
    partial_output: str,
    cause: ProviderErrorClass = ProviderErrorClass.PROVIDER_UNAVAILABLE,
    message: str = "",
    raw_payload: str = "",
) -> ProviderError:
    """Mid-stream failure: classified distinctly, partial output preserved.

    A stream that dies halfway through must NOT look like a clean pre-flight
    rejection — downstream needs to know output was truncated (#176 req 4).
    """
    return ProviderError(
        error_class=cause,
        message=message
        or f"{adapter} stream failed after partial output ({len(partial_output)} chars)",
        adapter=adapter,
        hint=DEFAULT_RETRY_HINTS[cause],
        raw_payload=raw_payload,
        streaming_failure=True,
        partial_output=partial_output,
    )
