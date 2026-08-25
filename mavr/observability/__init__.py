"""Observability subsystem (spec §14).

Public surface:

- :mod:`mavr.observability.logging` — structlog + secret redaction
- :mod:`mavr.observability.context` — correlation-id context vars
- :mod:`mavr.observability.events` — system event bus / SSE source
- :mod:`mavr.observability.metrics` — counters / gauges / histograms
- :mod:`mavr.observability.bundle` — redacted run-bundle export
"""
from __future__ import annotations

from mavr.observability.context import (
    bind,
    bind_structlog,
    clear_structlog,
    current_correlation,
    new_correlation_id,
)
from mavr.observability.events import (
    VALID_SEVERITIES,
    EventBus,
    SystemEvent,
    filter_events,
)
from mavr.observability.logging import configure_logging, get_logger
from mavr.observability.metrics import (
    MetricPoint,
    MetricsStore,
    merge_breakdowns,
)

__all__ = [
    "EventBus",
    "MetricPoint",
    "MetricsStore",
    "SystemEvent",
    "VALID_SEVERITIES",
    "bind",
    "bind_structlog",
    "clear_structlog",
    "configure_logging",
    "current_correlation",
    "filter_events",
    "get_logger",
    "merge_breakdowns",
    "new_correlation_id",
]
