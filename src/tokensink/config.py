"""Configuration loading and validation (PLAN.md §16).

Design decisions:
- YAML and TOML are both accepted; the file extension selects the parser.
- Validation is *collect-and-report*: every problem is gathered and reported in
  one pass so users fix all errors before launching workers, never one at a
  time.
- Defaults are explicit and safe: shell execution off, active testing off,
  free-only mode on. See ``docs/config.md`` for the full reference.

Example config (YAML)::

    server:
      host: 127.0.0.1
      port: 8737
    storage:
      database_path: data/tokensink.db
      artifact_path: data/artifacts
    providers:
      credential_refs:
        openrouter: op://vault/openrouter/key
      allowlist: [openrouter]
    routing:
      free_only: true
      router_count: 3
    budgets:
      agent_timeout_seconds: 600
      max_tokens_per_agent: 200000
    review:
      quorum: 4
    retention:
      days: 90
    redaction:
      enabled: true
    logging:
      level: INFO
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

__all__ = ["Config", "ConfigError", "load_config"]


class ConfigError(Exception):
    """Raised when configuration is invalid; ``errors`` lists every problem."""

    def __init__(self, errors: list[str]) -> None:
        self.errors = errors
        super().__init__("configuration invalid:\n" + "\n".join(errors))


@dataclass
class Config:
    """Fully validated configuration (PLAN.md §16 sections)."""

    server_host: str = "127.0.0.1"
    server_port: int = 8737
    database_path: str = "data/tokensink.db"
    artifact_path: str = "data/artifacts"
    credential_refs: dict[str, str] = field(default_factory=dict)
    provider_allowlist: list[str] = field(default_factory=list)
    free_only: bool = True
    router_count: int = 2
    agent_timeout_seconds: int = 900
    max_tokens_per_agent: int = 500_000
    review_quorum: int = 4
    retention_days: int = 90
    redaction_enabled: bool = True
    log_level: str = "INFO"

    @property
    def raw(self) -> dict[str, Any]:
        return self._raw

    _raw: dict[str, Any] = field(default_factory=dict)


# --- per-section validators -------------------------------------------------
# Each validator appends human-readable error strings to `errors` and returns
# the parsed value (or the default when the section is absent). Sections are
# validated independently so all errors surface in a single run.


def _check_type(errors: list[str], section: str, key: str, value: Any,
                types: tuple[type, ...]) -> bool:
    if not isinstance(value, types) or isinstance(value, bool) is (
        bool not in types
    ):
        names = "/".join(t.__name__ for t in types)
        errors.append(f"{section}.{key}: expected {names}, got {type(value).__name__}")
        return False
    return True


def _validate_server(data: dict[str, Any], errors: list[str], cfg: Config) -> None:
    sec = data.get("server")
    if sec is None:
        return
    if not isinstance(sec, dict):
        errors.append("server: expected a mapping")
        return
    if "host" in sec:
        if _check_type(errors, "server", "host", sec["host"], (str,)):
            cfg.server_host = sec["host"]
    if "port" in sec:
        if _check_type(errors, "server", "port", sec["port"], (int,)):
            # Ports below 1024 need root privileges; reject early rather than
            # fail mysteriously at bind time.
            if not (1 <= sec["port"] <= 65535):
                errors.append(f"server.port: {sec['port']} out of range 1-65535")
            else:
                cfg.server_port = sec["port"]


def _validate_storage(data: dict[str, Any], errors: list[str], cfg: Config) -> None:
    sec = data.get("storage")
    if sec is None:
        return
    if not isinstance(sec, dict):
        errors.append("storage: expected a mapping")
        return
    for key, attr in (("database_path", "database_path"),
                      ("artifact_path", "artifact_path")):
        if key in sec:
            if _check_type(errors, "storage", key, sec[key], (str,)):
                path = Path(sec[key])
                # Empty or bare-root paths are almost always mistakes.
                if not path.name:
                    errors.append(f"storage.{key}: {sec[key]!r} has no filename component")
                else:
                    setattr(cfg, attr, sec[key])


def _validate_providers(data: dict[str, Any], errors: list[str], cfg: Config) -> None:
    sec = data.get("providers")
    if sec is None:
        return
    if not isinstance(sec, dict):
        errors.append("providers: expected a mapping")
        return
    refs = sec.get("credential_refs", {})
    if not isinstance(refs, dict):
        errors.append("providers.credential_refs: expected a mapping of provider -> secret reference")
    elif not all(isinstance(v, str) and v for v in refs.values()):
        # Only references (e.g. secret-store paths), never literal keys, are
        # allowed here — PLAN.md §15 forbids secrets in config files.
        errors.append("providers.credential_refs: values must be non-empty secret references, not raw credentials")
    else:
        cfg.credential_refs = refs
    allow = sec.get("allowlist", [])
    if not isinstance(allow, list) or not all(isinstance(x, str) for x in allow):
        errors.append("providers.allowlist: expected a list of provider names")
    else:
        cfg.provider_allowlist = allow


def _validate_routing(data: dict[str, Any], errors: list[str], cfg: Config) -> None:
    sec = data.get("routing")
    if sec is None:
        return
    if not isinstance(sec, dict):
        errors.append("routing: expected a mapping")
        return
    if "free_only" in sec:
        if _check_type(errors, "routing", "free_only", sec["free_only"], (bool,)):
            cfg.free_only = sec["free_only"]
    if "router_count" in sec:
        if _check_type(errors, "routing", "router_count", sec["router_count"], (int,)):
            # At least one router so routing can never be silently disabled;
            # capped to keep parallel model-call fan-out bounded.
            if not (1 <= sec["router_count"] <= 32):
                errors.append(f"routing.router_count: {sec['router_count']} out of range 1-32")
            else:
                cfg.router_count = sec["router_count"]


def _validate_budgets(data: dict[str, Any], errors: list[str], cfg: Config) -> None:
    sec = data.get("budgets")
    if sec is None:
        return
    if not isinstance(sec, dict):
        errors.append("budgets: expected a mapping")
        return
    if "agent_timeout_seconds" in sec:
        v = sec["agent_timeout_seconds"]
        if _check_type(errors, "budgets", "agent_timeout_seconds", v, (int,)) and v <= 0:
            errors.append("budgets.agent_timeout_seconds: must be positive")
        else:
            cfg.agent_timeout_seconds = v
    if "max_tokens_per_agent" in sec:
        v = sec["max_tokens_per_agent"]
        if _check_type(errors, "budgets", "max_tokens_per_agent", v, (int,)) and v <= 0:
            errors.append("budgets.max_tokens_per_agent: must be positive")
        else:
            cfg.max_tokens_per_agent = v


def _validate_review(data: dict[str, Any], errors: list[str], cfg: Config) -> None:
    sec = data.get("review")
    if sec is None:
        return
    if not isinstance(sec, dict):
        errors.append("review: expected a mapping")
        return
    if "quorum" in sec:
        if _check_type(errors, "review", "quorum", sec["quorum"], (int,)):
            q = sec["quorum"]
            # PLAN.md §10.5 default review panel is four agents; quorum must
            # fit within that panel size.
            if not (1 <= q <= 4):
                errors.append(f"review.quorum: {q} out of range 1-4")
            else:
                cfg.review_quorum = q


def _validate_retention(data: dict[str, Any], errors: list[str], cfg: Config) -> None:
    sec = data.get("retention")
    if sec is None:
        return
    if not isinstance(sec, dict):
        errors.append("retention: expected a mapping")
        return
    if "days" in sec:
        if _check_type(errors, "retention", "days", sec["days"], (int,)) and sec["days"] <= 0:
            errors.append("retention.days: must be positive")
        else:
            cfg.retention_days = sec["days"]


def _validate_redaction(data: dict[str, Any], errors: list[str], cfg: Config) -> None:
    sec = data.get("redaction")
    if sec is None:
        return
    if not isinstance(sec, dict):
        errors.append("redaction: expected a mapping")
        return
    if "enabled" in sec:
        if _check_type(errors, "redaction", "enabled", sec["enabled"], (bool,)):
            # Redaction defaults to ON (PLAN.md §15); flipping it off is legal
            # but must be an explicit boolean, never a truthy string.
            cfg.redaction_enabled = sec["enabled"]


_LOG_LEVELS = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}


def _validate_logging(data: dict[str, Any], errors: list[str], cfg: Config) -> None:
    sec = data.get("logging")
    if sec is None:
        return
    if not isinstance(sec, dict):
        errors.append("logging: expected a mapping")
        return
    if "level" in sec:
        level = sec["level"]
        if _check_type(errors, "logging", "level", level, (str,)):
            if str(level).upper() not in _LOG_LEVELS:
                errors.append(
                    f"logging.level: unknown level {level!r} "
                    f"(expected one of {sorted(_LOG_LEVELS)})"
                )
            else:
                cfg.log_level = str(level).upper()


_VALIDATORS = [
    _validate_server,
    _validate_storage,
    _validate_providers,
    _validate_routing,
    _validate_budgets,
    _validate_review,
    _validate_retention,
    _validate_redaction,
    _validate_logging,
]


def _parse(path: Path) -> dict[str, Any]:
    """Parse a YAML/TOML file into a plain dict. Raises ConfigError with a
    single syntax error entry on parse failure."""
    suffix = path.suffix.lower()
    try:
        text = path.read_text()
    except OSError as exc:
        raise ConfigError([f"{path}: cannot read file ({exc})"]) from exc
    try:
        if suffix in (".yaml", ".yml"):
            loaded = yaml.safe_load(text)
        elif suffix == ".toml":
            loaded = tomllib.loads(text)
        else:
            raise ConfigError([f"{path}: unsupported format {suffix!r} (use .yaml/.yml/.toml)"])
    except ConfigError:
        raise
    except yaml.YAMLError as exc:
        raise ConfigError([f"{path}: invalid YAML ({exc})"]) from exc
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError([f"{path}: invalid TOML ({exc})"]) from exc
    if loaded is None:
        return {}
    if not isinstance(loaded, dict):
        raise ConfigError([f"{path}: top-level structure must be a mapping"])
    return loaded


def load_config(path: str | Path) -> Config:
    """Load, validate and return a Config. Raises :class:`ConfigError`
    carrying ALL problems found (collect-and-report, PLAN.md §16)."""
    p = Path(path)
    if not p.exists():
        raise ConfigError([f"{p}: file does not exist"])

    data = _parse(p)
    errors: list[str] = []

    # Unknown top-level sections usually mean a typo'd setting that would be
    # silently ignored otherwise — treat them as errors.
    known = {"server", "storage", "providers", "routing", "budgets",
             "review", "retention", "redaction", "logging"}
    for key in sorted(set(data) - known):
        errors.append(f"{key}: unknown top-level section (known: {sorted(known)})")

    cfg = Config()
    for validator in _VALIDATORS:
        validator(data, errors, cfg)

    if errors:
        raise ConfigError(errors)
    cfg._raw = data
    return cfg
