"""Failure classification for the agent runtime (spec §6).

Errors are bucketed into four classes so the orchestrator knows
whether to retry (transient), quarantine (permanent / policy), or
send to the model-quality review (model_quality).
"""
from __future__ import annotations

from enum import Enum
from typing import Any


class FailureClass(str, Enum):
    TRANSIENT = "transient"
    PERMANENT = "permanent"
    POLICY = "policy"
    MODEL_QUALITY = "model_quality"
    CANCELLED = "cancelled"


class FailureError(RuntimeError):
    def __init__(
        self,
        message: str,
        *,
        classification: FailureClass,
        cause: BaseException | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.classification = classification
        self.cause = cause
        self.details = details or {}


# ---- markers / detection --------------------------------------------------


class TransientMarker:
    """Marker base class for transient (retryable) errors."""


class PermanentMarker:
    """Marker base class for permanent (non-retryable) errors."""


class PolicyViolation(Exception):
    """Raised when a task violates campaign scope or system policy."""


class ModelQualityError(Exception):
    """Raised when an agent's output is malformed, hallucinates structure,
    or otherwise fails downstream validation in a way that suggests a
    model-quality issue rather than a transient infrastructure problem.
    """


class BudgetExceeded(Exception):
    """Raised when an agent exhausts its token/time/tool/request budget."""

    def __init__(self, kind: str, used: int, limit: int) -> None:
        super().__init__(f"budget exhausted: {kind}={used}/{limit}")
        self.kind = kind
        self.used = used
        self.limit = limit


def classify(exc: BaseException) -> FailureClass:
    """Map an exception to a :class:`FailureClass`.

    The mapping is conservative: anything we don't recognize is treated
    as transient so we get another chance to observe it.
    """
    if isinstance(exc, PolicyViolation):
        return FailureClass.POLICY
    if isinstance(exc, ModelQualityError):
        return FailureClass.MODEL_QUALITY
    if isinstance(exc, BudgetExceeded):
        return FailureClass.PERMANENT
    if isinstance(exc, PermanentMarker):
        return FailureClass.PERMANENT
    transient_types = (TransientMarker, asyncio.TimeoutError, ConnectionError, OSError)
    if isinstance(exc, transient_types):
        return FailureClass.TRANSIENT
    if isinstance(exc, asyncio.CancelledError):
        return FailureClass.CANCELLED
    return FailureClass.TRANSIENT


import asyncio  # noqa: E402  (placed after class defs for grouping)
