"""Failure handling: classification, retry policies, dead-letter queue.

Implements the failure-handling matrix from PLAN.md §18 (tracked in issue #25).

Every failure that occurs anywhere in the system is mapped to a
:class:`FailureClass`. The class determines whether retrying is allowed, which
:class:`RetryPolicy` applies, and what happens when retries are exhausted
(quarantine, dead-letter, or human intervention).

Design rules (from §18):

- Retries only for classified *transient* failures. Anything permanent,
  policy-driven, or safety-relevant must never be silently retried.
- Failed inputs and outputs are preserved for diagnosis via
  :class:`FailureRecord`; callers are responsible for redacting secrets before
  attaching payloads (the redaction pipeline lives in its own subsystem).
- Each failure class maps to a documented recovery path — see
  ``docs/failure-handling.md``.
"""

from __future__ import annotations

import enum
import random
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any


class FailureClass(enum.Enum):
    """Failure classes from PLAN.md §18, each with a fixed recovery path."""

    # --- transient: retry with backoff is allowed -------------------------
    PROVIDER_OUTAGE = "provider_outage"  # network/5xx → retry, then failover
    PROVIDER_RATE_LIMIT = "provider_rate_limit"  # 429 → honor backoff/cooldown
    AGENT_TIMEOUT = "agent_timeout"  # retry once with smaller scope, then human
    DATABASE_TRANSIENT = "database_transient"  # lock/busy → short retry, then halt
    UI_DISCONNECT = "ui_disconnect"  # client-level; stream replay recovers

    # --- non-retryable: deterministic or policy outcomes ------------------
    QUOTA_EXHAUSTED = "quota_exhausted"  # no point retrying until window resets
    UNKNOWN_MODEL_STATUS = "unknown_model_status"  # excluded from free-only routing
    ROUTER_DISAGREEMENT = "router_disagreement"  # needs coordinator/consensus path
    MALFORMED_OUTPUT = "malformed_output"  # schema validation failed
    SEARCH_EXTRACTION_FAILURE = "search_extraction_failure"
    SCOPE_POLICY_REJECTION = "scope_policy_rejection"  # NEVER retried; blocked event
    DB_INTEGRITY = "db_integrity"  # crash/interrupt → recovery, not retry
    CONFLICTING_EDITS = "conflicting_edits"  # merge/versioning resolution needed

    # --- safety-critical: quarantine + human intervention only ------------
    POC_SAFETY_FAILURE = "poc_safety_failure"  # hard stop, approval gate required
    STALE_LEASE = "stale_lease"  # reassignment via lease manager
    MODEL_QUALITY = "model_quality"  # wrong-but-valid output; negative score signal


# Classes where retrying is permitted at all. Everything else goes straight to
# its terminal recovery path — this set is intentionally small (§18: "retries
# only for classified transient failures").
TRANSIENT_CLASSES = frozenset(
    {
        FailureClass.PROVIDER_OUTAGE,
        FailureClass.PROVIDER_RATE_LIMIT,
        FailureClass.AGENT_TIMEOUT,
        FailureClass.DATABASE_TRANSIENT,
        FailureClass.UI_DISCONNECT,
    }
)

# Terminal recovery paths.
RECOVERY_PATHS: dict[FailureClass, str] = {
    FailureClass.PROVIDER_OUTAGE: "retry_then_failover",
    FailureClass.PROVIDER_RATE_LIMIT: "retry_with_cooldown",
    FailureClass.AGENT_TIMEOUT: "retry_once_then_human",
    FailureClass.DATABASE_TRANSIENT: "retry_then_halt",
    FailureClass.UI_DISCONNECT: "replay_on_reconnect",
    FailureClass.QUOTA_EXHAUSTED: "wait_for_window",
    FailureClass.UNKNOWN_MODEL_STATUS: "exclude_from_free_routing",
    FailureClass.ROUTER_DISAGREEMENT: "coordinator_consensus",
    FailureClass.MALFORMED_OUTPUT: "dead_letter",
    FailureClass.SEARCH_EXTRACTION_FAILURE: "dead_letter",
    FailureClass.SCOPE_POLICY_REJECTION: "blocked_event_no_retry",
    FailureClass.DB_INTEGRITY: "crash_recovery",
    FailureClass.CONFLICTING_EDITS: "versioned_merge_resolution",
    FailureClass.POC_SAFETY_FAILURE: "quarantine_human_approval",
    FailureClass.STALE_LEASE: "lease_reassignment",
    # Not retried on the same model — the score system (#17) consumes it as a
    # negative signal and the router may pick a different model instead.
    FailureClass.MODEL_QUALITY: "negative_score_signal_then_reroute",
}


@dataclass(frozen=True)
class RetryPolicy:
    """Backoff parameters for one failure class.

    ``max_attempts`` counts total attempts including the first, so 3 means two
    retries after the initial failure.
    """

    max_attempts: int
    base_delay_s: float
    max_delay_s: float
    jitter: bool = True

    def delay_for(self, attempt: int, rng: Callable[[], float] | None = None) -> float:
        """Exponential backoff delay before ``attempt`` (1-based) re-execution.

        When ``jitter`` is set the delay is scaled by a random factor in
        [0.5, 1.0) (decorrelated-ish jitter) so concurrent retriers do not
        synchronize. ``rng`` is injectable for deterministic tests.
        """
        delay = self.base_delay_s * (2 ** (attempt - 1))
        delay = min(delay, self.max_delay_s)
        if self.jitter and delay > 0:
            r = rng if rng is not None else _default_rng.random
            delay *= 0.5 + r() * 0.5  # uniform in [0.5, 1.0)
        return delay


# Module-level so tests can monkeypatch deterministically without touching
# instances; random.random is only consulted when jitter is enabled.
_default_rng = random.Random()


DEFAULT_RETRY_POLICIES: dict[FailureClass, RetryPolicy] = {
    # Rate limits back off more aggressively and cap lower than outages so we
    # never contribute to a thundering herd against an already-struggling API.
    FailureClass.PROVIDER_OUTAGE: RetryPolicy(3, 1.0, 30.0),
    FailureClass.PROVIDER_RATE_LIMIT: RetryPolicy(4, 2.0, 60.0),
    FailureClass.AGENT_TIMEOUT: RetryPolicy(2, 0.0, 0.0),
    FailureClass.DATABASE_TRANSIENT: RetryPolicy(3, 0.1, 2.0),
    FailureClass.UI_DISCONNECT: RetryPolicy(5, 0.5, 10.0),
}


def classify(
    exc: BaseException,
    *,
    rules: list[tuple[str, FailureClass]] | None = None,
) -> FailureClass:
    """Map a provider/agent exception to a failure class.

    Two-stage classification per §8.1/§6:

    1. **Data-driven rules** (optional): provider adapters contribute
       ``(pattern, FailureClass)`` pairs — matched against the exception type
       name and message, case-insensitively, in order. This is how an adapter
       teaches the classifier about vendor-specific errors without this module
       importing the adapter.
    2. **Built-in type-name heuristics**: well-known names so subsystems can
       raise plain builtins without importing this module.

    Unknown exceptions default to a non-transient class so we never burn
    retries on something we do not understand (§18 rule). A wrong-but-well-
    formed answer from a model (detected by callers via validation of *valid*
    output against expectations) should be raised as ``ModelQualityError`` —
    it routes to the score system as a negative signal instead of a retry.
    """
    haystack = " ".join((type(exc).__name__.lower(), str(exc).lower()))

    for pattern, failure_class in rules or []:
        if pattern.lower() in haystack:
            return failure_class

    if "modelquality" in haystack.replace("_", ""):
        return FailureClass.MODEL_QUALITY
    if "timeout" in haystack:
        return FailureClass.AGENT_TIMEOUT
    if "ratelimit" in haystack.replace("_", "") or "toomanyrequests" in haystack:
        return FailureClass.PROVIDER_RATE_LIMIT
    if "quota" in haystack:
        return FailureClass.QUOTA_EXHAUSTED
    if "json" in haystack or "schema" in haystack or "malformed" in haystack:
        return FailureClass.MALFORMED_OUTPUT
    if "connection" in haystack or "unavailable" in haystack or isinstance(exc, OSError):
        return FailureClass.PROVIDER_OUTAGE
    # Conservative default: non-transient, dead-letter with diagnosis payload.
    return FailureClass.MALFORMED_OUTPUT


class ModelQualityError(Exception):
    """A model returned schema-valid output that is substantively wrong.

    Raising this (rather than returning the bad value) lets :func:`classify`
    route it to ``MODEL_QUALITY``: no same-model retry, but a negative signal
    to the score system (#17) and optional reroute to a different model.
    """


@dataclass
class FailureRecord:
    """Preserved input/output for diagnosis of a single failure (§18).

    Payloads MUST be redacted by the caller before attachment — this record is
    written to durable storage verbatim.
    """

    failure_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    failure_class: FailureClass | None = None
    component: str = ""
    message: str = ""
    redacted_input: Any = None
    redacted_output: Any = None
    created_at: float = field(default_factory=time.time)


@dataclass
class RetryOutcome:
    """Result of a :func:`with_retry` run."""

    value: Any = None
    exhausted: bool = False
    attempts: int = 0
    last_failure: FailureRecord | None = None


def with_retry(
    fn: Callable[[], Any],
    failure_class: FailureClass,
    policy: RetryPolicy | None = None,
    on_failure: Callable[[FailureRecord, int], None] | None = None,
    sleep: Callable[[float], None] = time.sleep,
) -> RetryOutcome:
    """Run ``fn`` honoring the retry policy for ``failure_class``.

    Non-transient classes execute exactly once. Every failed attempt emits a
    redacted :class:`FailureRecord` to ``on_failure`` (the caller's hook into
    persistence/dead-lettering). When retries are exhausted the caller decides
    the terminal path — this function never raises.
    """
    pol = policy or DEFAULT_RETRY_POLICIES.get(failure_class)
    if failure_class not in TRANSIENT_CLASSES or pol is None:
        pol = RetryPolicy(max_attempts=1, base_delay_s=0, max_delay_s=0)
    outcome = RetryOutcome()
    for attempt in range(1, pol.max_attempts + 1):
        outcome.attempts = attempt
        try:
            outcome.value = fn()
            return outcome
        except Exception as exc:  # noqa: BLE001 - boundary records everything
            record = FailureRecord(
                failure_class=failure_class,
                message=f"{type(exc).__name__}: {exc}",
            )
            outcome.last_failure = record
            if on_failure is not None:
                on_failure(record, attempt)
            if attempt == pol.max_attempts:
                outcome.exhausted = True
                return outcome
            sleep(pol.delay_for(attempt))
    return outcome  # pragma: no cover - loop always returns inside


class DeadLetterQueue:
    """In-memory dead-letter queue for unroutable/unrecoverable work (§18).

    Subsystems append items they gave up on; operators drain and inspect them.
    Kept deliberately tiny here — production backing store belongs to the
    storage layer.
    """

    def __init__(self) -> None:
        self._items: list[tuple[FailureRecord, Any]] = []

    def put(self, record: FailureRecord, payload: Any) -> None:
        self._items.append((record, payload))

    def drain(self) -> list[tuple[FailureRecord, Any]]:
        items, self._items = self._items, []
        return items

    def __len__(self) -> int:
        return len(self._items)


class RetryBudget:
    """Per-task and per-campaign retry budgets to prevent retry loops (§18).

    Every retry attempt must consume budget from BOTH scopes: a task that
    keeps failing stops burning campaign-wide attempts, and one noisy task
    cannot starve the rest of the campaign. When either budget is exhausted
    the caller escalates to the dead-letter path instead of retrying.

    Budgets are plain counters — the durable backing store belongs to the
    storage layer (#7); this class defines the contract.
    """

    def __init__(
        self,
        *,
        task_retries: int = 3,
        campaign_retries: int = 50,
        campaigns: dict[str, int] | None = None,
    ) -> None:
        self.task_retries = task_retries
        # Per-campaign caps are configurable; "default" covers campaigns with
        # no explicit entry so they still get a sane cap instead of unbounded.
        self.campaign_budgets = {"default": campaign_retries, **(campaigns or {})}
        self.task_spent: dict[str, int] = {}
        self.campaign_spent: dict[str, int] = {}

    def can_retry(self, task_id: str, campaign_id: str = "default") -> bool:
        """True if both the task and its campaign have remaining budget."""
        return self.task_spent.get(task_id, 0) < self.task_retries and self.campaign_spent.get(
            campaign_id, 0
        ) < self.campaign_budgets.get(campaign_id, 0)

    def spend(self, task_id: str, campaign_id: str = "default") -> None:
        """Consume one unit of retry budget for this attempt."""
        self.task_spent[task_id] = self.task_spent.get(task_id, 0) + 1
        self.campaign_spent[campaign_id] = self.campaign_spent.get(campaign_id, 0) + 1


class FailureLogger:
    """Observability hook recording every classification and retry decision.

    Keeps (task, class, decision, reason) tuples so the audit log (§14/§15)
    can answer "why did this task get retried / dead-lettered". The in-memory
    list is the interface; durable storage goes through observability (#14).
    """

    def __init__(self) -> None:
        self.entries: list[dict[str, Any]] = []

    def log(
        self,
        task_id: str,
        failure_class: FailureClass,
        decision: str,
        reason: str,
    ) -> None:
        self.entries.append(
            {
                "task_id": task_id,
                "failure_class": failure_class.value,
                "decision": decision,
                "reason": reason,
                "ts": time.time(),
            }
        )
