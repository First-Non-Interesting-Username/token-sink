"""tokensink config package (PLAN §4 layout; implementation in loader.py)."""

from .loader import (
    Config,
    ConfigError,
    load_config,
    load_config_collect,
    validate_dict,
)

__all__ = ["Config", "ConfigError", "load_config", "load_config_collect", "validate_dict"]
"""Configuration loading and startup validation (PLAN §16)."""
