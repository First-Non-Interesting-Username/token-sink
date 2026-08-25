"""Pydantic v2 schemas for Phase 4 — provider adapters, router pool, model catalog.

These types complement the persistent entities in :mod:`mavr.schemas.entities`.
They describe the wire-level request/response shapes that the router and
adapters exchange in-process. They are deliberately separate from the DB
entities because they carry adapter-specific fields (e.g. ``trust_level``,
``fallback_chain``) that are not stored long-term.
"""
from __future__ import annotations

import re
from datetime import UTC, datetime
from enum import Enum
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator

from mavr.schemas.entities import SCHEMA_VERSION, Uuid

# ---- shared --------------------------------------------------------------


class _Base(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True, protected_namespaces=())
    schema_version: str = SCHEMA_VERSION


# ---- task / routing request ---------------------------------------------


class TaskCategory(str, Enum):
    """Spec §8.3 — task categories used for routing and scoring."""

    DISCOVERY = "discovery"
    REVIEW = "review"
    EXTRACTION = "extraction"
    SEARCH_QUERY = "search_query"
    POC = "poc"
    IMPACT = "impact"
    POLISH = "polish"
    FINAL_REVIEW = "final_review"
    GENERIC = "generic"


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class RoutingPolicy(str, Enum):
    BEST_SCORE = "best_score_within_budget"
    FASTEST_ELIGIBLE = "fastest_eligible"
    CONSENSUS = "consensus"
    DIVERSITY = "diversity"


class ChatMessage(_Base):
    role: Literal["system", "user", "assistant", "tool"]
    content: str

    @field_validator("content")
    @classmethod
    def _content_nonempty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("message content must not be empty")
        return v


class ToolSpec(_Base):
    name: str
    description: str
    parameters: dict[str, Any] = Field(default_factory=dict)


class ChatRequest(_Base):
    """Provider-agnostic chat request used by every adapter."""

    messages: list[ChatMessage]
    tools: list[ToolSpec] = Field(default_factory=list)
    max_tokens: int | None = None
    temperature: float = 0.0
    response_format: Literal["text", "json_object"] = "text"
    stop: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class UsageInfo(_Base):
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    cache_write_tokens: int = 0
    is_free: bool = True
    estimated_cost: float = 0.0


class ChatResponse(_Base):
    content: str
    finish_reason: Literal["stop", "length", "tool_call", "error", "cancelled"] = "stop"
    tool_calls: list[dict[str, Any]] = Field(default_factory=list)
    usage: UsageInfo = Field(default_factory=UsageInfo)
    raw: dict[str, Any] = Field(default_factory=dict)


# ---- router decision ----------------------------------------------------


class RouterCandidate(_Base):
    provider_id: str
    model_key: str
    score: float = 0.0
    expected_cost: float = 0.0
    rationale: str = ""
    confidence: float = 0.0

    @field_validator("score", "confidence")
    @classmethod
    def _in_range(cls, v: float) -> float:
        if not (0.0 <= v <= 1.0):
            raise ValueError("score/confidence must be in [0, 1]")
        return v


class RouterDecisionModel(_Base):
    """Wire-level router decision; the DB row mirrors it via :class:`mavr.schemas.entities.RouterDecision`."""

    router_id: str
    candidates: list[RouterCandidate] = Field(default_factory=list)
    chosen: RouterCandidate | None = None
    fallback_chain: list[str] = Field(default_factory=list)
    rationale: str = ""
    confidence: float = 0.0
    expected_cost: float = 0.0
    policy: RoutingPolicy = RoutingPolicy.BEST_SCORE

    @field_validator("confidence")
    @classmethod
    def _in_range(cls, v: float) -> float:
        if not (0.0 <= v <= 1.0):
            raise ValueError("confidence must be in [0, 1]")
        return v


class RoutingTask(_Base):
    """The unit of work the router pool dispatches."""

    task_id: Uuid
    campaign_id: Uuid | None = None
    agent_id: Uuid | None = None
    category: TaskCategory = TaskCategory.GENERIC
    risk: RiskLevel = RiskLevel.LOW
    policy: RoutingPolicy = RoutingPolicy.BEST_SCORE
    request: ChatRequest
    free_only: bool = True
    require_diversity: bool = False
    budget_tokens: int | None = None
    budget_cost: float | None = None
    allow_paid_override: bool = False
    human_approved: bool = False


# ---- provider capability / health ---------------------------------------


_AuthStatusStr = Literal["ok", "missing", "invalid"]  # noqa: F401 — public via HealthReport

AuthStatusStr = _AuthStatusStr  # type alias re-exported


class AdapterCapabilities(_Base):
    streaming: bool = False
    tool_support: bool = False
    structured_output: bool = False
    context_limit: int | None = None
    rate_limit_rpm: int | None = None
    request_timeout_seconds: float = 30.0


class HealthReport(_Base):
    ok: bool
    latency_ms: int | None = None
    auth_status: _AuthStatusStr
    detail: str = ""
    checked_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class HealthCheckResult(_Base):
    provider_id: str
    health: HealthReport


# ---- model catalog (declarative) ---------------------------------------


_ProviderId = Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_-]{1,63}$")]
_ModelKey = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9._:/\-]{1,128}$")]


class TrustLevel(str, Enum):
    NATIVE_FREE = "native_free"
    PARTLY_FREE_GATEWAY = "partly_free_gateway"
    OPENAI_COMPAT = "openai_compat"
    PAID_ONLY = "paid_only"


class ModelCatalogEntry(_Base):
    """Declarative description of a model — its free status, limits, and metadata.

    Entries are written into a Python module (under ``mavr/providers/model_catalog/``)
    and bootstrapped into the DB on first use. They never carry secrets.
    """

    provider_id: _ProviderId
    model_key: _ModelKey
    display_name: str
    free: bool
    free_status: Literal["confirmed", "unknown", "paid"]
    trust_level: TrustLevel
    context_limit: int
    tool_support: bool = False
    structured_output: bool = False
    streaming: bool = True
    rate_limit_rpm: int | None = None
    pricing_input_per_mtok: float | None = None
    pricing_output_per_mtok: float | None = None
    notes: str = ""
    expires_at: datetime | None = None
    last_verified: datetime | None = None
    categories: list[TaskCategory] = Field(default_factory=list)

    @field_validator("display_name")
    @classmethod
    def _display_nonempty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("display_name must not be empty")
        return v


# ---- model score --------------------------------------------------------


class ModelScore(_Base):
    provider_id: str
    model_key: str
    category: TaskCategory
    score: float
    sample_count: int
    confidence_low: float
    confidence_high: float
    recency_weight: float = 1.0
    source: Literal["benchmark", "live", "manual"] = "benchmark"
    last_updated: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @field_validator("score", "confidence_low", "confidence_high", "recency_weight")
    @classmethod
    def _bounded(cls, v: float) -> float:
        if not (0.0 <= v <= 1.0):
            raise ValueError("score values must be in [0, 1]")
        return v

    @field_validator("sample_count")
    @classmethod
    def _non_negative(cls, v: int) -> int:
        if v < 0:
            raise ValueError("sample_count must be >= 0")
        return v


# ---- circuit breaker state ---------------------------------------------


class CircuitState(str, Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class CircuitBreakerState(_Base):
    provider_id: str
    model_key: str
    state: CircuitState = CircuitState.CLOSED
    failures: int = 0
    successes: int = 0
    opened_at: datetime | None = None
    cooldown_until: datetime | None = None
    last_failure_at: datetime | None = None
    last_error: str = ""


# ---- benchmark ----------------------------------------------------------


class BenchmarkPrompt(_Base):
    """A single offline benchmark prompt.

    ``expected`` is a structured check the harness runs against the
    response — for example a substring match, a JSON-shape check, or a
    list of must-contain tokens. No sensitive data ever lives here.
    """

    id: str
    category: TaskCategory
    messages: list[ChatMessage]
    must_contain: list[str] = Field(default_factory=list)
    must_not_contain: list[str] = Field(default_factory=list)
    max_tokens: int | None = None
    weight: float = 1.0

    @field_validator("id")
    @classmethod
    def _id_nonempty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("prompt id must not be empty")
        return v

    @field_validator("weight")
    @classmethod
    def _weight_positive(cls, v: float) -> float:
        if v <= 0:
            raise ValueError("weight must be > 0")
        return v


# ---- provider errors ---------------------------------------------------


class ProviderErrorReason(str, Enum):
    AUTH = "auth"
    RATE_LIMIT = "rate_limit"
    OVERLOADED = "overloaded"
    NETWORK = "network"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"
    MODEL_ERROR = "model_error"
    POLICY = "policy"
    UNKNOWN = "unknown"


class ProviderError(RuntimeError):
    """Normalized adapter error; carries a reason and retryability hint."""

    def __init__(
        self,
        reason: ProviderErrorReason,
        message: str,
        *,
        retryable: bool = True,
        http_status: int | None = None,
        provider_id: str | None = None,
    ) -> None:
        super().__init__(message)
        self.reason = reason
        self.retryable = retryable
        self.http_status = http_status
        self.provider_id = provider_id

    def __repr__(self) -> str:  # pragma: no cover — debug helper
        return (
            f"ProviderError(reason={self.reason!r}, retryable={self.retryable}, "
            f"http_status={self.http_status}, provider_id={self.provider_id!r})"
        )


# ---- dead-letter -------------------------------------------------------


class DeadLetterReason(str, Enum):
    NO_CANDIDATES = "no_candidates"
    POLICY_VIOLATION = "policy_violation"
    CIRCUIT_OPEN = "circuit_open"
    TIMEOUT = "timeout"
    UNROUTABLE = "unroutable"
    ERROR = "error"


class DeadLetterEntry(_Base):
    task_id: Uuid | None = None
    campaign_id: Uuid | None = None
    reason: DeadLetterReason
    detail: str = ""
    payload: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


# ---- registry summary --------------------------------------------------


_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


def is_uuid(value: str) -> bool:
    return bool(_UUID_RE.match(value))
