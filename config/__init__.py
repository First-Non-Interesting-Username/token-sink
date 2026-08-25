"""token_sink configuration: YAML/TOML loading + startup validation (PLAN.md §16)."""

from .loader import (
    Config,
    ConfigError,
    ConfigValidationError,
    from_dict,
    load,
    load_raw,
    validate,
)

__all__ = [
    "Config",
    "ConfigError",
    "ConfigValidationError",
    "from_dict",
    "load",
    "load_raw",
    "validate",
]
