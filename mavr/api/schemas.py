"""Pydantic v2 request/response models for the API."""
from __future__ import annotations

import re
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


def _is_uuid(value: str) -> bool:
    return bool(_UUID_RE.match(value))


class _Base(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class ApprovalCreateRequest(_Base):
    action: Literal["active_testing", "submission", "scope_change", "deletion"]
    actor: str = Field(min_length=1, max_length=200)
    reason: str = Field(default="", max_length=2000)
    campaign_id: str | None = None
    finding_id: str | None = None
    ttl_seconds: int = Field(default=900, ge=1, le=86400)

    @field_validator("campaign_id", "finding_id")
    @classmethod
    def _uuid_or_none(cls, v: str | None) -> str | None:
        if v is None or v == "":
            return None
        if not _is_uuid(v):
            raise ValueError("must be a UUID")
        return v


class CampaignNewRequest(_Base):
    name: str = Field(min_length=1, max_length=200)
    description: str = Field(default="", max_length=4000)
    target_spec: dict[str, Any] = Field(default_factory=dict)
    duration_hours: int = Field(default=24, ge=1, le=720)
    token_budget: int = Field(default=0, ge=0)
    tool_budget: int = Field(default=0, ge=0)
    config_snapshot: dict[str, Any] = Field(default_factory=dict)


class ScopePolicyRequest(_Base):
    campaign_id: str
    allowed_targets: list[str] = Field(default_factory=list)
    allowed_methods: list[str] = Field(default_factory=list)
    action_allowlist: list[str] = Field(default_factory=list)
    rate_limit_per_minute: int = Field(default=60, ge=0, le=10000)
    active_testing: bool = False
    explicit_unsafe_networking: bool = False


class ProviderTestRequest(_Base):
    provider_id: str = Field(min_length=1)


class MetricPointRequest(_Base):
    name: str = Field(min_length=1, max_length=200)
    kind: Literal["counter", "gauge", "histogram"]
    value: float
    dimensions: dict[str, Any] = Field(default_factory=dict)
    is_free: bool = True
    is_paid: bool = False
    campaign_id: str | None = None


class EventPublishRequest(_Base):
    event_type: str = Field(min_length=1, max_length=200)
    payload: dict[str, Any] = Field(default_factory=dict)
    severity: Literal["debug", "info", "warning", "error"] = "info"
    campaign_id: str | None = None
    agent_id: str | None = None
    task_id: str | None = None
    finding_id: str | None = None


class CampaignExportRequest(_Base):
    campaign_id: str
    output_path: str | None = None


class KillSwitchRequest(_Base):
    active: bool
    reason: str = Field(default="", max_length=2000)
    by: str = Field(default="human", max_length=200)


__all__ = [
    "ApprovalCreateRequest",
    "CampaignExportRequest",
    "CampaignNewRequest",
    "EventPublishRequest",
    "KillSwitchRequest",
    "MetricPointRequest",
    "ProviderTestRequest",
    "ScopePolicyRequest",
]
