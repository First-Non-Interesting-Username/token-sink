"""Configuration loading and startup validation (PLAN.md §16).

Design notes:
- YAML is the primary format; TOML is accepted as a fallback so operators can
  pick either. Both are parsed into the same plain-dict intermediate form.
- Validation COLLECTS all errors and reports them together before anything
  launches (§16: "report all errors before launching workers"), rather than
  failing fast on the first problem.
- Every error message names the offending config key so the operator can fix
  it directly.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


class ConfigError(Exception):
    """One configuration problem. `key` is the dotted path of the bad key."""

    def __init__(self, key: str, message: str):
        self.key = key
        self.message = message
        super().__init__(f"{key}: {message}")


@dataclass
class Config:
    """Validated configuration (all fields below are required unless noted)."""

    # Server (§16)
    server_host: str = "127.0.0.1"
    server_port: int = 8080
    # Storage paths (§16); created on demand by the storage layer.
    db_path: Path = Path("data/token_sink.db")
    artifact_path: Path = Path("data/artifacts")
    # Providers (§16). credential_refs are references (e.g. env var names),
    # never inline secret values — AGENTS.md forbids committing live secrets.
    provider_credential_refs: dict[str, str] = field(default_factory=dict)
    provider_allowlist: list[str] = field(default_factory=list)
    model_allowlist: list[str] = field(default_factory=list)
    free_only_mode: bool = False
    # Routers / runtime budgets (§16)
    router_count: int = 2
    router_concurrency: int = 4
    agent_budget_tokens: int = 200_000
    agent_timeout_seconds: int = 600
    # Search/extraction settings (§16)
    search_enabled: bool = True
    search_cache_ttl_seconds: int = 86_400
    extraction_backend: str = "curl"  # one of: curl, jina
    # Campaign defaults (§16)
    campaign_defaults: dict[str, Any] = field(default_factory=dict)
    # Scope & active-testing policy (§16) — safe defaults; active testing must
    # be opted into explicitly per PLAN.md §2 principle 5.
    scope_enforcement: bool = True
    allow_active_testing: bool = False
    # Review quorum (§16)
    review_quorum: int = 2
    # Retention & redaction (§16)
    retention_days: int | None = None
    redact_prompts: bool = True
    # Logging & telemetry (§16)
    log_level: str = "INFO"
    telemetry_enabled: bool = False


# Dotted-key -> (min, max) range specs for generic integer checks.
# server.port is validated explicitly in validate(); the rest live here.
_INT_KEYS = {
    "routers.count": (1, 64),
    "routers.concurrency": (1, 256),
    "agents.budget_tokens": (1, None),
    "agents.timeout_seconds": (1, None),
    "search.cache_ttl_seconds": (0, None),
    "review.quorum": (1, None),
}
_BOOL_KEYS = {
    "providers.free_only_mode",
    "search.enabled",
    "policy.scope_enforcement",
    "policy.allow_active_testing",
    "logging.redact_prompts",
    "logging.telemetry_enabled",
}
_STR_LIST_KEYS = {"providers.model_allowlist"}
_EXTRACTION_BACKENDS = {"curl", "jina"}
_LOG_LEVELS = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}

# Top-level sections we know about; unknown ones are reported as errors so a
# typo like "providrs:" doesn't silently drop settings.
_KNOWN_SECTIONS = {
    "server", "storage", "providers", "routers", "agents",
    "search", "campaign_defaults", "policy", "review",
    "retention", "logging",
}


def _load_yaml(path: Path) -> dict[str, Any]:
    import yaml  # deferred so TOML-only users don't need PyYAML installed

    with open(path) as f:
        return yaml.safe_load(f) or {}


def _load_toml(path: Path) -> dict[str, Any]:
    import tomllib

    with open(path, "rb") as f:
        return tomllib.load(f)


def load_raw(path: str | Path) -> dict[str, Any]:
    """Load a YAML or TOML file into a raw dict based on extension."""
    path = Path(path)
    if not path.exists():
        raise ConfigError(str(path), "config file does not exist")
    suffix = path.suffix.lower()
    try:
        if suffix in (".yaml", ".yml"):
            data = _load_yaml(path)
        elif suffix == ".toml":
            data = _load_toml(path)
        else:
            raise ConfigError(str(path), f"unsupported config format '{suffix}' (use .yaml/.yml or .toml)")
    except ConfigError:
        raise
    except Exception as exc:  # parse error — surface it verbatim
        raise ConfigError(str(path), f"parse error: {exc}") from exc
    if not isinstance(data, dict):
        raise ConfigError(str(path), "top level must be a mapping")
    return data


def validate(data: dict[str, Any]) -> list[ConfigError]:
    """Validate a raw config dict. Returns ALL problems found (may be empty)."""
    errors: list[ConfigError] = []

    for section in data:
        if section not in _KNOWN_SECTIONS:
            errors.append(ConfigError(section, f"unknown section (expected one of: {', '.join(sorted(_KNOWN_SECTIONS))})"))

    def get(dotted: str) -> tuple[Any, bool]:
        """Resolve a dotted key against nested mappings.

        Returns (value, True) when present, (None, False) when absent. If an
        intermediate node exists but is not a mapping, records a structural
        error instead of silently pretending the key is absent — §16 says
        report ALL problems, and `server: oops` is a problem.
        """
        node: Any = data
        parts = dotted.split(".")
        for part in parts:
            if not isinstance(node, dict):
                # intermediate node was a scalar; already reported below
                return None, False
            if part not in node:
                return None, False
            node = node[part]
        return node, True

    # Structural check: any section we know about must be a mapping, so a
    # typo like `server: 8080` is reported rather than ignored.
    for section in _KNOWN_SECTIONS & data.keys():
        if not isinstance(data[section], dict):
            errors.append(ConfigError(section, "must be a mapping"))

    # server
    host, ok = get("server.host")
    if ok and not isinstance(host, str):
        errors.append(ConfigError("server.host", "must be a string"))
    port, ok = get("server.port")
    if ok:
        if not isinstance(port, int) or isinstance(port, bool) or port < 1 or port > 65535:
            errors.append(ConfigError("server.port", "must be an integer in [1, 65535]"))

    # storage paths must be strings (not opened here — no side effects at validation time)
    for key in ("storage.db_path", "storage.artifact_path"):
        val, ok = get(key)
        if ok and not isinstance(val, str):
            errors.append(ConfigError(key, "must be a filesystem path string"))

    # providers
    creds, ok = get("providers.credential_refs")
    if ok:
        if not isinstance(creds, dict):
            errors.append(ConfigError("providers.credential_refs", "must be a mapping of provider -> credential reference (env var name or secret path, never an inline value)"))
        else:
            for prov, ref in creds.items():
                if not isinstance(ref, str):
                    errors.append(ConfigError(f"providers.credential_refs.{prov}", "credential reference must be a string"))
    allow, ok = get("providers.allowlist")
    if ok and not (isinstance(allow, list) and all(isinstance(x, str) for x in allow)):
        errors.append(ConfigError("providers.allowlist", "must be a list of provider names"))
    mallow, ok = get("providers.model_allowlist")
    if ok and not (isinstance(mallow, list) and all(isinstance(x, str) for x in mallow)):
        errors.append(ConfigError("providers.model_allowlist", "must be a list of model names"))

    # integer-with-range keys
    for key, (lo, hi) in _INT_KEYS.items():
        val, ok = get(key)
        if ok:
            if not isinstance(val, int) or isinstance(val, bool) or val < lo or (hi is not None and val > hi):
                rng = f">= {lo}" if hi is None else f"in [{lo}, {hi}]"
                errors.append(ConfigError(key, f"must be an integer {rng}"))

    # boolean keys
    for key in _BOOL_KEYS:
        val, ok = get(key)
        if ok and not isinstance(val, bool):
            errors.append(ConfigError(key, "must be true or false"))

    # search.extraction_backend
    backend, ok = get("search.extraction_backend")
    if ok and backend not in _EXTRACTION_BACKENDS:
        errors.append(ConfigError("search.extraction_backend", f"must be one of: {', '.join(sorted(_EXTRACTION_BACKENDS))}"))

    # logging.level
    level, ok = get("logging.level")
    if ok and (not isinstance(level, str) or level.upper() not in _LOG_LEVELS):
        errors.append(ConfigError("logging.level", f"must be one of: {', '.join(sorted(_LOG_LEVELS))}"))

    # retention.days: positive int or null
    days, ok = get("retention.days")
    if ok and days is not None and (not isinstance(days, int) or isinstance(days, bool) or days < 1):
        errors.append(ConfigError("retention.days", "must be a positive integer or null"))

    # review quorum sanity: compare against the EFFECTIVE router count —
    # the explicit value if set, otherwise the Config default (2). Checking
    # only when both keys are present would let `review.quorum: 50` pass
    # while from_dict later defaults routers.count to 2.
    quorum, q_ok = get("review.quorum")
    rcount, r_ok = get("routers.count")
    effective_rcount = rcount if r_ok else Config().router_count
    if q_ok and isinstance(quorum, int) and isinstance(effective_rcount, int) and quorum > effective_rcount:
        errors.append(ConfigError("review.quorum", f"quorum ({quorum}) exceeds router count ({effective_rcount}); reviews could never complete"))

    return errors


def from_dict(data: dict[str, Any]) -> Config:
    """Build a Config from a validated raw dict. Raises only on programming error."""
    cfg = Config()

    def get(dotted: str, default):
        node: Any = data
        for part in dotted.split("."):
            if isinstance(node, dict) and part in node:
                node = node[part]
            else:
                return default
        return node

    cfg.server_host = get("server.host", cfg.server_host)
    cfg.server_port = get("server.port", cfg.server_port)
    cfg.db_path = Path(get("storage.db_path", str(cfg.db_path)))
    cfg.artifact_path = Path(get("storage.artifact_path", str(cfg.artifact_path)))
    cfg.provider_credential_refs = dict(get("providers.credential_refs", {}) or {})
    cfg.provider_allowlist = list(get("providers.allowlist", []) or [])
    cfg.model_allowlist = list(get("providers.model_allowlist", []) or [])
    cfg.free_only_mode = bool(get("providers.free_only_mode", cfg.free_only_mode))
    cfg.router_count = get("routers.count", cfg.router_count)
    cfg.router_concurrency = get("routers.concurrency", cfg.router_concurrency)
    cfg.agent_budget_tokens = get("agents.budget_tokens", cfg.agent_budget_tokens)
    cfg.agent_timeout_seconds = get("agents.timeout_seconds", cfg.agent_timeout_seconds)
    cfg.search_enabled = bool(get("search.enabled", cfg.search_enabled))
    cfg.search_cache_ttl_seconds = get("search.cache_ttl_seconds", cfg.search_cache_ttl_seconds)
    cfg.extraction_backend = get("search.extraction_backend", cfg.extraction_backend)
    cd = get("campaign_defaults", {})
    cfg.campaign_defaults = dict(cd) if isinstance(cd, dict) else {}
    cfg.scope_enforcement = bool(get("policy.scope_enforcement", cfg.scope_enforcement))
    cfg.allow_active_testing = bool(get("policy.allow_active_testing", cfg.allow_active_testing))
    cfg.review_quorum = get("review.quorum", cfg.review_quorum)
    cfg.retention_days = get("retention.days", cfg.retention_days)
    cfg.redact_prompts = bool(get("logging.redact_prompts", cfg.redact_prompts))
    cfg.telemetry_enabled = bool(get("logging.telemetry_enabled", cfg.telemetry_enabled))
    level = get("logging.level", None)
    if isinstance(level, str):
        cfg.log_level = level.upper()
    return cfg


def load(path: str | Path) -> Config:
    """Convenience: load + validate + build.

    Raises ConfigValidationError carrying every problem if any are found.
    """
    data = load_raw(path)
    errors = validate(data)
    if errors:
        raise ConfigValidationError(errors)
    return from_dict(data)


class ConfigValidationError(Exception):
    """All configuration problems found at startup, reported together."""

    def __init__(self, errors: list[ConfigError]):
        self.errors = errors
        lines = "\n".join(f"  - {e.key}: {e.message}" for e in errors)
        super().__init__(f"configuration invalid ({len(errors)} error(s)):\n{lines}")
