"""Configuration loading and validation (PLAN.md §16).

Design decisions (documented per AGENTS.md):

- YAML is the primary config format. TOML was considered but YAML keeps the
  example config and docs consistent with a single parser; adding a TOML
  loader later only requires extending ``load_config``.
- Validation COLLECTS all errors instead of failing on the first one, so an
  operator fixes everything in a single startup round-trip (§16 requirement).
- Every error message points at the offending config key path
  (e.g. ``server.port``), never at a raw Python exception.
- Credentials are stored as *references* (env var names / keyring paths),
  never literal secret values — see PLAN §15.
- Unknown top-level sections are rejected: typos like ``servor.host`` must
  not silently disable the intended section's validation.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

# All top-level config sections we understand. Anything outside this set is
# an error so that renamed/misspelled sections surface immediately.
KNOWN_SECTIONS = {
    "server",
    "storage",
    "providers",
    "router",
    "agents",
    "search",
    "campaign_defaults",
    "scope_policy",
    "review",
    "retention",
    "logging",
}


class ConfigError(Exception):
    """Aggregated configuration errors; ``errors`` lists each message."""

    def __init__(self, errors: list[str]) -> None:
        self.errors = errors
        super().__init__("invalid configuration:\n" + "\n".join(f"  - {e}" for e in errors))


@dataclass
class ServerConfig:
    host: str = "127.0.0.1"
    port: int = 8080


@dataclass
class StorageConfig:
    db_path: str = "data/tokensink.db"
    artifact_path: str = "data/artifacts"


@dataclass
class ProviderRef:
    """A credential *reference*, not a value: resolved at use time from env."""

    name: str
    env_var: str


@dataclass
class ProvidersConfig:
    allowlist: list[str] = field(default_factory=list)
    model_allowlist: list[str] = field(default_factory=list)
    free_only: bool = True
    credentials: dict[str, str] = field(default_factory=dict)  # provider -> env var name


@dataclass
class RouterConfig:
    count: int = 2
    concurrency_per_router: int = 4


@dataclass
class AgentsConfig:
    budget_usd: float = 10.0
    request_timeout_s: int = 120
    heartbeat_interval_s: int = 30


@dataclass
class SearchConfig:
    engine: str = "ddgs"  # ddgs | curl | jina
    cache_ttl_s: int = 3600
    max_results: int = 10
    timeout_s: int = 30


@dataclass
class CampaignDefaultsConfig:
    max_findings: int = 100
    default_review_quorum: int = 2


@dataclass
class ScopePolicyConfig:
    # Active testing is denied by default; enabling it is an explicit,
    # reviewed operator decision (PLAN §15 safety posture).
    active_testing_allowed: bool = False
    allowed_actions: list[str] = field(default_factory=lambda: ["recon", "passive"])
    prohibited_actions: list[str] = field(default_factory=list)
    rate_limit_requests_per_min: int = 60


@dataclass
class ReviewConfig:
    quorum: int = 2
    require_independent_reviewers: bool = True


@dataclass
class RetentionConfig:
    days: int = 365
    redact_secrets_in_logs: bool = True


@dataclass
class LoggingConfig:
    level: str = "INFO"
    file_path: str | None = None
    telemetry_enabled: bool = False


@dataclass
class Config:
    server: ServerConfig = field(default_factory=ServerConfig)
    storage: StorageConfig = field(default_factory=StorageConfig)
    providers: ProvidersConfig = field(default_factory=ProvidersConfig)
    router: RouterConfig = field(default_factory=RouterConfig)
    agents: AgentsConfig = field(default_factory=AgentsConfig)
    search: SearchConfig = field(default_factory=SearchConfig)
    campaign_defaults: CampaignDefaultsConfig = field(default_factory=CampaignDefaultsConfig)
    scope_policy: ScopePolicyConfig = field(default_factory=ScopePolicyConfig)
    review: ReviewConfig = field(default_factory=ReviewConfig)
    retention: RetentionConfig = field(default_factory=RetentionConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)


def load_config(path: str | Path) -> Config:
    """Load + validate a YAML config file. Raises ConfigError with ALL errors."""
    p = Path(path)
    errors: list[str] = []
    if not p.exists():
        raise ConfigError([f"config file not found: {p}"])
    try:
        raw = yaml.safe_load(p.read_text()) or {}
    except yaml.YAMLError as e:
        raise ConfigError([f"{p}: invalid YAML: {e}"]) from None
    if not isinstance(raw, dict):
        raise ConfigError([f"{p}: top-level document must be a mapping"])
    cfg, errors = validate_dict(raw)
    if errors:
        raise ConfigError(errors)
    return cfg


def _err(errors: list[str], key: str, msg: str) -> None:
    errors.append(f"{key}: {msg}")


def _require_int(
    d: dict,
    lookup_key: str,
    msg_key: str,
    errors: list[str],
    *,
    min_v: int | None = None,
    max_v: int | None = None,
) -> int | None:
    v = d.get(lookup_key)
    if v is None:
        _err(errors, msg_key, "required")
        return None
    if not isinstance(v, int) or isinstance(v, bool):
        _err(errors, msg_key, f"must be an integer, got {type(v).__name__}")
        return None
    if min_v is not None and v < min_v:
        _err(errors, msg_key, f"must be >= {min_v}, got {v}")
    if max_v is not None and v > max_v:
        _err(errors, msg_key, f"must be <= {max_v}, got {v}")
    return v


def _opt_int(
    d: dict,
    lookup_key: str,
    msg_key: str,
    errors: list[str],
    *,
    min_v: int | None = None,
) -> int | None:
    v = d.get(lookup_key)
    if v is None:
        return None
    if not isinstance(v, int) or isinstance(v, bool):
        _err(errors, msg_key, f"must be an integer, got {type(v).__name__}")
        return None
    if min_v is not None and v < min_v:
        _err(errors, msg_key, f"must be >= {min_v}, got {v}")
    return v


def _str_list(d: dict, key: str, errors: list[str]) -> list[str] | None:
    v = d.get(key)
    if v is None:
        return None
    if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
        _err(errors, key, "must be a list of strings")
        return None
    return v


def validate_dict(raw: Any) -> tuple[Config, list[str]]:
    """Validate a raw mapping; returns (config, errors). Exposed for tests."""
    errors: list[str] = []
    cfg = Config()
    if not isinstance(raw, dict):
        return cfg, ["top-level document must be a mapping"]

    for k in raw:
        if k not in KNOWN_SECTIONS:
            _err(
                errors,
                k,
                f"unknown section (expected one of: {', '.join(sorted(KNOWN_SECTIONS))})",
            )

    # -- server ------------------------------------------------------------
    s = raw.get("server") or {}
    if isinstance(s, dict):
        if "host" in s:
            if isinstance(s["host"], str) and s["host"]:
                cfg.server.host = s["host"]
            else:
                _err(errors, "server.host", "must be a non-empty string")
        port = (
            _require_int(s, "port", "server.port", errors, min_v=1, max_v=65535)
            if "port" in s
            else None
        )
        if port is not None and not any("server.port" in e for e in errors):
            cfg.server.port = port
    else:
        _err(errors, "server", "must be a mapping")

    # -- storage -----------------------------------------------------------
    st = raw.get("storage") or {}
    if isinstance(st, dict):
        for key, attr in (("db_path", "db_path"), ("artifact_path", "artifact_path")):
            if key in st:
                v = st[key]
                if isinstance(v, str) and v.strip():
                    setattr(cfg.storage, attr, v)
                    # Reject obviously unsafe artifact paths up front (§12).
                    if ".." in Path(v).parts:
                        _err(errors, f"storage.{key}", "must not contain '..' path segments")
                else:
                    _err(errors, f"storage.{key}", "must be a non-empty string")
    else:
        _err(errors, "storage", "must be a mapping")

    # -- providers ---------------------------------------------------------
    pr = raw.get("providers") or {}
    if isinstance(pr, dict):
        al = _str_list(pr, "allowlist", errors)
        if al is not None:
            cfg.providers.allowlist = al
        mal = _str_list(pr, "model_allowlist", errors)
        if mal is not None:
            cfg.providers.model_allowlist = mal
        fo = pr.get("free_only")
        if fo is not None:
            if isinstance(fo, bool):
                cfg.providers.free_only = fo
            else:
                _err(errors, "providers.free_only", "must be a boolean")
        creds = pr.get("credentials")
        if creds is not None:
            # Values must look like environment variable NAMES, never secrets.
            if not isinstance(creds, dict) or not all(
                isinstance(k, str) and isinstance(v, str) for k, v in creds.items()
            ):
                _err(errors, "providers.credentials", "must map provider name -> env var name")
            else:
                for prov, var in creds.items():
                    if not var.isidentifier() or var.islower():
                        _err(
                            errors,
                            f"providers.credentials.{prov}",
                            f"value '{var}' does not look like an env var name "
                            "(credentials are references, never literal values — PLAN §15)",
                        )
                    elif var not in os.environ:
                        # Warn-level error: referenced credential missing now may
                        # appear before workers launch, but fail closed by default.
                        _err(
                            errors,
                            f"providers.credentials.{prov}",
                            f"referenced env var '{var}' is not set",
                        )
                cfg.providers.credentials = creds
    else:
        _err(errors, "providers", "must be a mapping")

    # -- router ------------------------------------------------------------
    r = raw.get("router") or {}
    if isinstance(r, dict):
        c = r.get("count")
        if c is not None:
            if isinstance(c, int) and not isinstance(c, bool) and c >= 1:
                cfg.router.count = c
            else:
                _err(errors, "router.count", "must be an integer >= 1")
        cc = r.get("concurrency_per_router")
        if cc is not None:
            if isinstance(cc, int) and not isinstance(cc, bool) and cc >= 1:
                cfg.router.concurrency_per_router = cc
            else:
                _err(errors, "router.concurrency_per_router", "must be an integer >= 1")
    else:
        _err(errors, "router", "must be a mapping")

    # -- agents ------------------------------------------------------------
    a = raw.get("agents") or {}
    if isinstance(a, dict):
        b = a.get("budget_usd")
        if b is not None:
            if isinstance(b, int | float) and not isinstance(b, bool) and b > 0:
                cfg.agents.budget_usd = float(b)
            else:
                _err(errors, "agents.budget_usd", "must be a positive number")
        t = a.get("request_timeout_s")
        if t is not None:
            if isinstance(t, int) and not isinstance(t, bool) and t >= 1:
                cfg.agents.request_timeout_s = t
            else:
                _err(errors, "agents.request_timeout_s", "must be an integer >= 1")
        hb = a.get("heartbeat_interval_s")
        if hb is not None:
            if isinstance(hb, int) and not isinstance(hb, bool) and hb >= 1:
                cfg.agents.heartbeat_interval_s = hb
            else:
                _err(errors, "agents.heartbeat_interval_s", "must be an integer >= 1")
    else:
        _err(errors, "agents", "must be a mapping")

    # -- search ------------------------------------------------------------
    se = raw.get("search") or {}
    if isinstance(se, dict):
        eng = se.get("engine")
        if eng is not None:
            if eng in ("ddgs", "curl", "jina"):
                cfg.search.engine = eng
            else:
                _err(errors, "search.engine", f"unknown engine '{eng}' (ddgs/curl/jina)")
        ttl = _opt_int(se, "cache_ttl_s", "search.cache_ttl_s", errors, min_v=0)
        if ttl is not None and not any("search.cache_ttl_s" in e for e in errors):
            cfg.search.cache_ttl_s = ttl
        mr = _opt_int(se, "max_results", "search.max_results", errors, min_v=1)
        if mr is not None and not any("search.max_results" in e for e in errors):
            cfg.search.max_results = mr
        to = _opt_int(se, "timeout_s", "search.timeout_s", errors, min_v=1)
        if to is not None and not any("search.timeout_s" in e for e in errors):
            cfg.search.timeout_s = to
    else:
        _err(errors, "search", "must be a mapping")

    # -- campaign defaults ---------------------------------------------------
    cd = raw.get("campaign_defaults") or {}
    if isinstance(cd, dict):
        mf = _opt_int(cd, "max_findings", "campaign_defaults.max_findings", errors, min_v=1)
        if mf is not None and not any("campaign_defaults.max_findings" in e for e in errors):
            cfg.campaign_defaults.max_findings = mf
    else:
        _err(errors, "campaign_defaults", "must be a mapping")

    # -- scope policy --------------------------------------------------------
    sp = raw.get("scope_policy") or {}
    if isinstance(sp, dict):
        ata = sp.get("active_testing_allowed")
        if ata is not None:
            if isinstance(ata, bool):
                cfg.scope_policy.active_testing_allowed = ata
            else:
                _err(errors, "scope_policy.active_testing_allowed", "must be a boolean")
        aa = _str_list(sp, "allowed_actions", errors)
        if aa is not None:
            cfg.scope_policy.allowed_actions = aa
        pa = _str_list(sp, "prohibited_actions", errors)
        if pa is not None:
            cfg.scope_policy.prohibited_actions = pa
        rl = _opt_int(
            sp,
            "rate_limit_requests_per_min",
            "scope_policy.rate_limit_requests_per_min",
            errors,
            min_v=1,
        )
        if rl is not None and not any(
            "scope_policy.rate_limit_requests_per_min" in e for e in errors
        ):
            cfg.scope_policy.rate_limit_requests_per_min = rl
    else:
        _err(errors, "scope_policy", "must be a mapping")

    # -- review --------------------------------------------------------------
    rv = raw.get("review") or {}
    if isinstance(rv, dict):
        q = _opt_int(rv, "quorum", "review.quorum", errors, min_v=1)
        if q is not None and not any("review.quorum" in e for e in errors):
            cfg.review.quorum = q
        rir = rv.get("require_independent_reviewers")
        if rir is not None:
            if isinstance(rir, bool):
                cfg.review.require_independent_reviewers = rir
            else:
                _err(errors, "review.require_independent_reviewers", "must be a boolean")
    else:
        _err(errors, "review", "must be a mapping")

    # -- retention -------------------------------------------------------------
    rt = raw.get("retention") or {}
    if isinstance(rt, dict):
        days = _opt_int(rt, "days", "retention.days", errors, min_v=1)
        if days is not None and not any("retention.days" in e for e in errors):
            cfg.retention.days = days
        rs = rt.get("redact_secrets_in_logs")
        if rs is not None:
            if isinstance(rs, bool):
                cfg.retention.redact_secrets_in_logs = rs
            else:
                _err(errors, "retention.redact_secrets_in_logs", "must be a boolean")
    else:
        _err(errors, "retention", "must be a mapping")

    # -- logging -----------------------------------------------------------------
    lg = raw.get("logging") or {}
    if isinstance(lg, dict):
        lvl = lg.get("level")
        if lvl is not None:
            if lvl in ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"):
                cfg.logging.level = lvl
            else:
                _err(errors, "logging.level", f"unknown level '{lvl}'")
        fp = lg.get("file_path")
        if fp is not None:
            if isinstance(fp, str):
                cfg.logging.file_path = fp
            else:
                _err(errors, "logging.file_path", "must be a string")
        tel = lg.get("telemetry_enabled")
        if tel is not None:
            if isinstance(tel, bool):
                cfg.logging.telemetry_enabled = tel
            else:
                _err(errors, "logging.telemetry_enabled", "must be a boolean")
    else:
        _err(errors, "logging", "must be a mapping")

    return cfg, errors


def load_config_collect(path: str | Path) -> tuple[Config, list[str]]:
    """Load a YAML file and validate it, collecting every error.

    Returns (config, errors); callers should refuse to launch workers when
    ``errors`` is non-empty (§16: report ALL errors before starting).
    """
    p = Path(path)
    if not p.exists():
        return Config(), [f"config file not found: {p}"]
    try:
        raw = yaml.safe_load(p.read_text()) or {}
    except yaml.YAMLError as e:
        return Config(), [f"{p}: invalid YAML: {e}"]
    return validate_dict(raw)
