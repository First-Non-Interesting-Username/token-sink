"""Structured logging via structlog.

Configures a single JSON (or console) processor pipeline and exposes
``get_logger``. Secret redaction is enforced via a dedicated processor
that scrubs any value for keys containing ``secret``, ``token``, or
``password`` (case-insensitive).
"""
from __future__ import annotations

import logging
import sys
from typing import Any

import structlog

_REDACT_KEYS = ("secret", "token", "password", "api_key", "apikey")
_REDACTED = "***REDACTED***"


def _redact_processor(_logger: Any, _method: str, event_dict: dict[str, Any]) -> dict[str, Any]:
    for key in list(event_dict.keys()):
        lk = key.lower()
        if any(r in lk for r in _REDACT_KEYS):
            event_dict[key] = _REDACTED
    return event_dict


def configure_logging(level: str = "INFO", json: bool = True) -> None:
    """Configure structlog + stdlib logging.

    Safe to call multiple times; re-configuring the root logger resets
    the handler list to avoid duplicate lines.
    """
    level_int = getattr(logging, level.upper(), logging.INFO)
    shared_processors: list[Any] = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        _redact_processor,
    ]

    if json:
        renderer: Any = structlog.processors.JSONRenderer()
    else:
        renderer = structlog.dev.ConsoleRenderer(colors=False)

    structlog.configure(
        processors=[*shared_processors, renderer],
        wrapper_class=structlog.make_filtering_bound_logger(level_int),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(file=sys.stderr),
        cache_logger_on_first_use=True,
    )

    root = logging.getLogger()
    for h in list(root.handlers):
        root.removeHandler(h)
    handler = logging.StreamHandler(sys.stderr)
    handler.setLevel(level_int)
    handler.setFormatter(logging.Formatter("%(message)s"))
    root.addHandler(handler)
    root.setLevel(level_int)


def get_logger(name: str | None = None) -> structlog.stdlib.BoundLogger:
    return structlog.get_logger(name)
