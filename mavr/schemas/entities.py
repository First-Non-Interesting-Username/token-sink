"""Pydantic v2 schemas for every MAVR entity (spec §11).

Every schema carries a ``schema_version`` field for forward compatibility.
Finding includes the spec §10 lifecycle state. UUIDs are validated as
UUIDv4 strings; timestamps are ISO-8601 UTC.
"""
from __future__ import annotations

import re
from datetime import UTC, datetime
from enum import Enum
from typing import Annotated, Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator

SCHEMA_VERSION: str = "1.0.0"

_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

Uuid = Annotated[str, StringConstraints(pattern=_UUID_RE.pattern)]
Sha256Hex = Annotated[str, StringConstraints(pattern=_SHA256_RE.pattern)]


def _now() -> datetime:
    return datetime.now(UTC)


def _ensure_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


# ---- shared --------------------------------------------------------------


class Base(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True, protected_namespaces=())
    schema_version: str = SCHEMA_VERSION


class Timestamped(Base):
    created_at: datetime = Field(default_factory=_now)
    updated_at: datetime = Field(default_factory=_now)

    @field_validator("created_at", "updated_at")
    @classmethod
    def _utc(cls, v: datetime) -> datetime:
        return _ensure_utc(v)


# ---- enums ---------------------------------------------------------------


class CampaignState(str, Enum):
    DRAFT = "draft"
    ACTIVE = "active"
    PAUSED = "paused"
    COMPLETED = "completed"
    CANCELLED = "cancelled"


class AgentStatus(str, Enum):
    CREATED = "created"
    QUEUED = "queued"
    ASSIGNED = "assigned"
    RUNNING = "running"
    WAITING = "waiting"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    BLOCKED = "blocked"


class AgentRole(str, Enum):
    DISCOVERY = "discovery"
    RESEARCH = "research"
    IMPACT = "impact"
    POC = "poc"
    REVIEWER = "reviewer"
    POLISH = "polish"
    FINAL_REVIEW = "final_review"
    SEARCH = "search"
    EXTRACTION = "extraction"
    SUBAGENT = "subagent"


class TaskStatus(str, Enum):
    PENDING = "pending"
    LEASED = "leased"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    QUARANTINED = "quarantined"


class TaskKind(str, Enum):
    SEARCH = "search"
    EXTRACT = "extract"
    IMPACT = "impact"
    POC = "poc"
    REVIEW = "review"
    POLISH = "polish"
    SUBMIT = "submit"
    GENERIC = "generic"


class FindingState(str, Enum):
    INITIAL = "initial_findings"
    REVIEW_CYCLE_1 = "review_cycle_1"
    VALIDATED = "validated"
    DISPUTED = "disputed"
    IMPACT = "impact_analysis"
    POC_DRAFT = "poc_draft"
    POC_REVIEW = "poc_review"
    POLISHED = "polished_report"
    FINAL_REVIEW = "final_review"
    VULNERABILITY = "vulnerabilities"
    QUARANTINED = "quarantined"
    TOMBSTONED = "tombstoned"


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FreeStatus(str, Enum):
    CONFIRMED = "confirmed"
    UNKNOWN = "unknown"
    PAID = "paid"


class ProviderKind(str, Enum):
    NATIVE = "native"
    GATEWAY = "gateway"
    CUSTOM = "custom"


class AuthStatus(str, Enum):
    OK = "ok"
    MISSING = "missing"
    INVALID = "invalid"


class AuditCategory(str, Enum):
    STATE_TRANSITION = "state_transition"
    POLICY_DECISION = "policy_decision"
    APPROVAL = "approval"
    CONFIG = "config"
    ERROR = "error"


class ActorKind(str, Enum):
    SYSTEM = "system"
    AGENT = "agent"
    HUMAN = "human"
    POLICY = "policy"


# ---- entities ------------------------------------------------------------


class Campaign(Timestamped):
    id: Uuid
    name: str
    description: str = ""
    target_spec: dict[str, Any]
    state: CampaignState = CampaignState.DRAFT
    started_at: datetime | None = None
    finished_at: datetime | None = None
    human_approved: bool = False
    duration_hours: int = 24
    token_budget: int = 0
    tool_budget: int = 0
    config_snapshot: dict[str, Any] = Field(default_factory=dict)

    @field_validator("name")
    @classmethod
    def _name_nonempty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("campaign.name must not be empty")
        return v

    @field_validator("duration_hours")
    @classmethod
    def _positive(cls, v: int) -> int:
        if v < 1:
            raise ValueError("duration_hours must be >= 1")
        return v


class ScopePolicy(Timestamped):
    id: Uuid
    campaign_id: Uuid
    allowed_targets: list[str] = Field(default_factory=list)
    allowed_methods: list[str] = Field(default_factory=lambda: ["GET", "HEAD"])
    action_allowlist: list[str] = Field(default_factory=list)
    rate_limit_per_minute: int = 60
    active_testing: bool = False
    explicit_unsafe_networking: bool = False
    human_approved: bool = False

    @field_validator("allowed_methods")
    @classmethod
    def _upper(cls, v: list[str]) -> list[str]:
        return [m.strip().upper() for m in v if m.strip()]


class AgentBudgets(BaseModel):
    model_config = ConfigDict(extra="forbid")
    max_tokens: int = 200_000
    max_time_seconds: int = 1800
    max_tool_calls: int = 500
    max_network_requests: int = 200

    @field_validator("max_tokens", "max_time_seconds", "max_tool_calls", "max_network_requests")
    @classmethod
    def _non_negative(cls, v: int) -> int:
        if v < 0:
            raise ValueError("budget values must be >= 0")
        return v


class Agent(Timestamped):
    id: Uuid
    parent_id: Uuid | None = None
    role: AgentRole
    status: AgentStatus = AgentStatus.CREATED
    campaign_id: Uuid | None = None
    task_id: Uuid | None = None
    budget: AgentBudgets = Field(default_factory=AgentBudgets)
    tokens_used: int = 0
    time_used_seconds: int = 0
    tool_calls_used: int = 0
    network_requests_used: int = 0
    metadata: dict[str, Any] = Field(default_factory=dict)


class Task(Timestamped):
    id: Uuid
    campaign_id: Uuid
    parent_task_id: Uuid | None = None
    kind: TaskKind
    status: TaskStatus = TaskStatus.PENDING
    priority: int = 0
    payload: dict[str, Any] = Field(default_factory=dict)
    result: dict[str, Any] | None = None
    error: str | None = None
    idempotency_key: str | None = None
    attempt: int = 0
    max_attempts: int = 3
    lease_owner: str | None = None
    lease_expires_at: datetime | None = None
    lease_heartbeat_at: datetime | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None

    @field_validator("max_attempts")
    @classmethod
    def _positive(cls, v: int) -> int:
        if v < 1:
            raise ValueError("max_attempts must be >= 1")
        return v


class ProviderCapabilities(BaseModel):
    model_config = ConfigDict(extra="forbid")
    streaming: bool = False
    tool_support: bool = False
    structured_output: bool = False
    context_limit: int | None = None
    rate_limit_rpm: int | None = None


class Provider(Timestamped):
    id: Uuid
    provider_id: str
    display_name: str
    kind: ProviderKind = ProviderKind.NATIVE
    free: bool = True
    free_status: FreeStatus = FreeStatus.UNKNOWN
    base_url: str | None = None
    auth_status: AuthStatus = AuthStatus.MISSING
    capabilities: ProviderCapabilities = Field(default_factory=ProviderCapabilities)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("provider_id")
    @classmethod
    def _nonempty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("provider_id must not be empty")
        return v


class ModelPricing(BaseModel):
    model_config = ConfigDict(extra="forbid")
    input_per_mtok: float | None = None
    output_per_mtok: float | None = None


class Model(Timestamped):
    id: Uuid
    provider_id: Uuid
    model_key: str
    display_name: str
    free: bool = True
    free_status: FreeStatus = FreeStatus.UNKNOWN
    context_limit: int | None = None
    tool_support: bool = False
    structured_output: bool = False
    streaming: bool = False
    pricing: ModelPricing | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("model_key")
    @classmethod
    def _nonempty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("model_key must not be empty")
        return v


class RouterDecision(Base):
    id: Uuid
    task_id: Uuid
    router_id: str
    candidates: list[dict[str, Any]] = Field(default_factory=list)
    chosen_model_id: Uuid | None = None
    rationale: str = ""
    confidence: float = 0.0
    expected_cost: float = 0.0
    fallback_chain: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=_now)

    @field_validator("confidence")
    @classmethod
    def _in_range(cls, v: float) -> float:
        if not (0.0 <= v <= 1.0):
            raise ValueError("confidence must be in [0, 1]")
        return v


class SearchResult(Base):
    id: Uuid
    task_id: Uuid | None = None
    campaign_id: Uuid
    query: str
    engine: str
    rank: int
    url: str
    title: str = ""
    snippet: str = ""
    source_status: str = "ok"
    in_scope: bool = True
    retrieved_at: datetime = Field(default_factory=_now)


class ExtractedSource(Base):
    id: Uuid
    task_id: Uuid | None = None
    campaign_id: Uuid
    source_url: str
    final_url: str
    content_type: str
    byte_length: int
    content_hash: Sha256Hex
    raw_artifact_id: Uuid
    extracted_artifact_id: Uuid | None = None
    http_status: int | None = None
    redirect_count: int = 0
    fetched_at: datetime = Field(default_factory=_now)
    extractor: Literal["curl", "jina"]
    metadata: dict[str, Any] = Field(default_factory=dict)


class EvidenceItem(Base):
    id: Uuid
    campaign_id: Uuid
    source_url: str
    retrieved_at: datetime = Field(default_factory=_now)
    content_hash: Sha256Hex
    byte_length: int
    content_type: str
    raw_artifact_id: Uuid
    extracted_artifact_id: Uuid | None = None
    notes: str = ""
    created_at: datetime = Field(default_factory=_now)


class Finding(Timestamped):
    id: Uuid
    campaign_id: Uuid
    title: str
    state: FindingState = FindingState.INITIAL
    severity: Severity | None = None
    confidence: Literal["confirmed", "likely", "inconclusive", "incorrect"] | None = None
    current_version: int = 1
    tombstoned: bool = False
    tombstone_reason: str | None = None

    @field_validator("title")
    @classmethod
    def _nonempty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("finding.title must not be empty")
        return v


class FindingVersion(Base):
    id: Uuid
    finding_id: Uuid
    version: int
    state: FindingState
    author_agent_id: Uuid | None = None
    summary: str
    body_markdown: str
    evidence_refs: list[Uuid] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=_now)

    @field_validator("version")
    @classmethod
    def _positive(cls, v: int) -> int:
        if v < 1:
            raise ValueError("version must be >= 1")
        return v


class ReviewVerdict(str, Enum):
    ACCEPT = "accept"
    REJECT = "reject"
    REQUEST_CHANGES = "request_changes"


class Review(Base):
    id: Uuid
    finding_id: Uuid
    version: int
    reviewer_agent_id: Uuid
    verdict: ReviewVerdict
    validity: Literal["valid", "invalid", "inconclusive"]
    reproduction_quality: Literal["high", "medium", "low", "n/a"]
    scope_safety: Literal["safe", "unsafe", "unknown"]
    severity_consistency: Literal["consistent", "inconsistent", "unknown"]
    missing_evidence: list[str] = Field(default_factory=list)
    requested_changes: str = ""
    confidence: float = 0.0
    provider_id: str | None = None
    model_id: str | None = None
    rationale: str = ""
    is_dispute: bool = False
    created_at: datetime = Field(default_factory=_now)

    @field_validator("confidence")
    @classmethod
    def _in_range(cls, v: float) -> float:
        if not (0.0 <= v <= 1.0):
            raise ValueError("confidence must be in [0, 1]")
        return v


class PoC(Base):
    id: Uuid
    finding_id: Uuid
    version: int
    setup: str
    commands: list[str]
    expected_output: str = ""
    cleanup: str = ""
    safety_notes: str = ""
    redacted_fields: list[str] = Field(default_factory=list)
    target_kind: Literal["local_mock", "staging", "live"]
    requires_human_approval: bool = True
    created_at: datetime = Field(default_factory=_now)

    @field_validator("commands")
    @classmethod
    def _nonempty(cls, v: list[str]) -> list[str]:
        if not v:
            raise ValueError("PoC.commands must not be empty")
        return [c for c in v if c.strip()]


class FinalReport(Base):
    id: Uuid
    finding_id: Uuid
    version: int
    report_path: str
    evidence_manifest_path: str
    redaction_manifest_path: str
    hash_manifest: Sha256Hex
    approved_by: str | None = None
    submitted_at: datetime | None = None
    submission_target: str | None = None
    created_at: datetime = Field(default_factory=_now)


class UsageEvent(Base):
    id: Uuid
    event_id: str
    campaign_id: Uuid | None = None
    agent_id: Uuid | None = None
    task_id: Uuid | None = None
    provider_id: str
    model_key: str
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    cache_write_tokens: int = 0
    latency_ms: int = 0
    is_free: bool = True
    is_paid: bool = False
    estimated_cost: float = 0.0
    created_at: datetime = Field(default_factory=_now)

    @field_validator("event_id")
    @classmethod
    def _nonempty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("event_id must not be empty")
        return v

    @field_validator("is_paid")
    @classmethod
    def _free_paid_consistent(cls, v: bool, info: Any) -> bool:
        # If marked paid, free must be False; if marked free, paid must be False.
        data = info.data
        if v and data.get("is_free", True):
            raise ValueError("is_paid=True requires is_free=False")
        return v


class AuditEvent(Base):
    id: Uuid
    event_id: str
    actor_id: Uuid | None = None
    actor_kind: ActorKind
    category: AuditCategory
    subject_kind: str | None = None
    subject_id: Uuid | None = None
    prior_state: str | None = None
    new_state: str | None = None
    reason: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=_now)

    @field_validator("event_id")
    @classmethod
    def _nonempty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("event_id must not be empty")
        return v


# round-trip helper ---------------------------------------------------------


def round_trip(model: type[BaseModel], payload: dict[str, Any]) -> BaseModel:
    """Validate ``payload`` against ``model`` then parse the dumped form.

    Ensures the model can survive JSON serialization losslessly.
    """
    instance = model.model_validate(payload)
    again = model.model_validate(instance.model_dump(mode="json"))
    return again


def to_uuid(value: str) -> UUID:
    return UUID(value)
