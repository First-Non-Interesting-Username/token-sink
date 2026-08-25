"""Configuration loader.

Settings are loaded from ``mavr/config/default.yaml`` and may be overridden
by an optional user config file (``MAVR_CONFIG`` env var, default
``~/.config/mavr/config.yaml``). All values are validated via pydantic v2
on load; all errors are collected and reported before workers start.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from mavr.observability.logging import get_logger

log = get_logger(__name__)

# ---- per-section models ----------------------------------------------------


class ServerConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    host: str = "127.0.0.1"
    port: int = 8765
    allow_lan: bool = False
    bearer_token_env: str = "MAVR_BEARER_TOKEN"

    @field_validator("host")
    @classmethod
    def _host_not_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("server.host must not be empty")
        return v

    @field_validator("port")
    @classmethod
    def _port_in_range(cls, v: int) -> int:
        if not (1 <= v <= 65535):
            raise ValueError("server.port must be in [1, 65535]")
        return v


class StorageConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    db_path: str = "~/.local/share/mavr/mavr.db"
    artifact_dir: str = "~/.local/share/mavr/artifacts"

    @field_validator("db_path", "artifact_dir")
    @classmethod
    def _no_parent_traversal(cls, v: str) -> str:
        if "\x00" in v:
            raise ValueError("path must not contain NUL bytes")
        return v


class ProviderConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    free: bool = True
    secret_name: str | None = None
    base_url: str | None = None
    notes: str = ""

    @field_validator("id")
    @classmethod
    def _id_nonempty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("provider id must not be empty")
        return v


class ProvidersConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    free_only: bool = True
    allowlists: dict[str, list[str]] = Field(default_factory=dict)
    providers: list[ProviderConfig] = Field(default_factory=list)

    @field_validator("allowlists")
    @classmethod
    def _no_empty_keys(cls, v: dict[str, list[str]]) -> dict[str, list[str]]:
        for k, vs in v.items():
            if not k.strip():
                raise ValueError("provider allowlist key must not be empty")
            for entry in vs:
                if not entry.strip():
                    raise ValueError(f"provider allowlist entry for {k!r} must not be empty")
        return v


class RoutersConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    count: int = 4
    concurrency: int = 8

    @field_validator("count", "concurrency")
    @classmethod
    def _positive(cls, v: int) -> int:
        if v < 1:
            raise ValueError("router count/concurrency must be >= 1")
        return v


class AgentBudget(BaseModel):
    model_config = ConfigDict(extra="forbid")

    max_tokens: int = 200_000
    max_time_seconds: int = 1800
    max_tool_calls: int = 500
    max_network_requests: int = 200

    @field_validator("max_tokens", "max_time_seconds", "max_tool_calls", "max_network_requests")
    @classmethod
    def _non_negative(cls, v: int) -> int:
        if v < 0:
            raise ValueError("agent budget values must be >= 0")
        return v


class AgentBudgetsConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    per_agent: AgentBudget = Field(default_factory=AgentBudget)


class SearchConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    top_n: int = 10
    safe_search: str = "moderate"
    max_bytes: int = 5_000_000
    max_redirects: int = 5
    request_timeout_seconds: int = 20
    allow_jina_fallback: bool = True

    @field_validator("top_n", "max_bytes", "max_redirects", "request_timeout_seconds")
    @classmethod
    def _positive(cls, v: int) -> int:
        if v < 1:
            raise ValueError("search numeric values must be >= 1")
        return v

    @field_validator("safe_search")
    @classmethod
    def _safe_search_known(cls, v: str) -> str:
        allowed = {"strict", "moderate", "off"}
        if v not in allowed:
            raise ValueError(f"search.safe_search must be one of {sorted(allowed)}")
        return v


class CampaignDefaults(BaseModel):
    model_config = ConfigDict(extra="forbid")

    duration_hours: int = 24
    require_human_approval_for_active_testing: bool = True
    require_human_approval_for_submission: bool = True

    @field_validator("duration_hours")
    @classmethod
    def _positive(cls, v: int) -> int:
        if v < 1:
            raise ValueError("campaign_defaults.duration_hours must be >= 1")
        return v


class ScopePolicyConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    default_allow_private_networks: bool = False
    default_allow_metadata_services: bool = False
    require_explicit_targets: bool = True
    method_allowlist: list[str] = Field(default_factory=lambda: ["GET", "HEAD"])
    rate_limit_per_minute: int = 60
    prohibited_action_classes: list[str] = Field(
        default_factory=lambda: [
            "denial_of_service",
            "destructive_mutation",
            "credential_attack",
            "data_exfiltration",
        ]
    )

    @field_validator("method_allowlist")
    @classmethod
    def _methods_upper(cls, v: list[str]) -> list[str]:
        out: list[str] = []
        for m in v:
            mu = m.strip().upper()
            if not mu:
                raise ValueError("method_allowlist entries must not be empty")
            out.append(mu)
        return out

    @field_validator("rate_limit_per_minute")
    @classmethod
    def _positive(cls, v: int) -> int:
        if v < 0:
            raise ValueError("scope_policy.rate_limit_per_minute must be >= 0")
        return v


class ReviewConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    quorum: str = "all_accept_or_3_of_4_no_blockers"
    reviewer_count: int = 4
    mode: str = "independent_first"

    @field_validator("reviewer_count")
    @classmethod
    def _valid_count(cls, v: int) -> int:
        if v < 1:
            raise ValueError("review.reviewer_count must be >= 1")
        return v

    @field_validator("mode")
    @classmethod
    def _known_mode(cls, v: str) -> str:
        if v not in {"independent_first", "discussion_first"}:
            raise ValueError("review.mode must be independent_first or discussion_first")
        return v


class RetentionConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    audit_log_days: int = 0
    artifact_days: int = 365

    @field_validator("audit_log_days", "artifact_days")
    @classmethod
    def _non_negative(cls, v: int) -> int:
        if v < 0:
            raise ValueError("retention days must be >= 0")
        return v


class LoggingConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    level: str = "INFO"
    json_output: bool = Field(default=True, alias="json")
    correlation_id_fields: list[str] = Field(
        default_factory=lambda: ["campaign_id", "agent_id", "task_id", "finding_id"]
    )

    @field_validator("level")
    @classmethod
    def _known_level(cls, v: str) -> str:
        allowed = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        if v.upper() not in allowed:
            raise ValueError(f"logging.level must be one of {sorted(allowed)}")
        return v.upper()


# ---- top-level settings ---------------------------------------------------


class AppConfig(BaseSettings):
    """Top-level MAVR configuration.

    Loaded from ``default.yaml`` (bundled) merged with the user config
    (env ``MAVR_CONFIG`` or ``~/.config/mavr/config.yaml``). The user
    config takes precedence.
    """

    model_config = SettingsConfigDict(
        env_prefix="MAVR_",
        env_nested_delimiter="__",
        extra="ignore",
        case_sensitive=False,
    )

    server: ServerConfig = Field(default_factory=ServerConfig)
    storage: StorageConfig = Field(default_factory=StorageConfig)
    providers: ProvidersConfig = Field(default_factory=ProvidersConfig)
    routers: RoutersConfig = Field(default_factory=RoutersConfig)
    agent_budgets: AgentBudgetsConfig = Field(default_factory=AgentBudgetsConfig)
    search: SearchConfig = Field(default_factory=SearchConfig)
    campaign_defaults: CampaignDefaults = Field(default_factory=CampaignDefaults)
    scope_policy: ScopePolicyConfig = Field(default_factory=ScopePolicyConfig)
    review: ReviewConfig = Field(default_factory=ReviewConfig)
    retention: RetentionConfig = Field(default_factory=RetentionConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)


# ---- loading helpers ------------------------------------------------------


_DEFAULT_CONFIG_PATH = Path(__file__).parent / "default.yaml"


def _load_yaml(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    if not isinstance(data, dict):
        raise ValueError(f"config file {path} is not a mapping")
    return data


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    out = dict(base)
    for k, v in override.items():
        if k in out and isinstance(out[k], dict) and isinstance(v, dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def _user_config_path() -> Path:
    env = os.environ.get("MAVR_CONFIG")
    if env:
        return Path(env).expanduser()
    return Path("~/.config/mavr/config.yaml").expanduser()


def load_config(path: str | os.PathLike[str] | None = None) -> AppConfig:
    """Load, merge, and validate the application configuration.

    If ``path`` is provided, it is used as the user-config overlay.
    """
    base = _load_yaml(_DEFAULT_CONFIG_PATH)

    overlay_path = Path(path).expanduser() if path is not None else _user_config_path()
    if overlay_path.exists():
        overlay = _load_yaml(overlay_path)
        base = _deep_merge(base, overlay)
    else:
        log.info("no_user_config", path=str(overlay_path))

    try:
        cfg = AppConfig.model_validate(base)
    except ValidationError as exc:
        log.error("config_validation_failed", errors=exc.errors())
        raise
    return cfg


def config_to_yaml(cfg: AppConfig) -> str:
    """Render a config back to YAML for inspection."""

    from pydantic import BaseModel as _BM

    def _to_dict(obj: Any) -> Any:
        if isinstance(obj, _BM):
            return {k: _to_dict(v) for k, v in obj.model_dump().items()}
        if isinstance(obj, dict):
            return {k: _to_dict(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [_to_dict(v) for v in obj]
        return obj

    return yaml.safe_dump(_to_dict(cfg), sort_keys=False)
