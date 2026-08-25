"""Correlation-id context (spec §14).

Use :func:`bind` to set the current correlation id (campaign, agent,
task, finding) for the duration of a context. All structlog records
emitted inside the context will carry the bound fields, and the API
layer propagates them to clients via the ``X-MAVR-Correlation-Id``
header.

The implementation uses :mod:`contextvars` so it is safe across
asyncio tasks. The bound ids are also passed to the DB-level event
publisher so they can be persisted.
"""
from __future__ import annotations

import secrets
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar

_corr: ContextVar[str] = ContextVar("mavr_correlation", default="")
_camp: ContextVar[str] = ContextVar("mavr_campaign", default="")
_agt: ContextVar[str] = ContextVar("mavr_agent", default="")
_tsk: ContextVar[str] = ContextVar("mavr_task", default="")
_find: ContextVar[str] = ContextVar("mavr_finding", default="")


def new_correlation_id() -> str:
    return f"corr_{secrets.token_hex(8)}"


def current_correlation() -> dict[str, str]:
    return {
        "correlation_id": _corr.get(),
        "campaign_id": _camp.get(),
        "agent_id": _agt.get(),
        "task_id": _tsk.get(),
        "finding_id": _find.get(),
    }


@contextmanager
def bind(
    *,
    correlation_id: str | None = None,
    campaign_id: str | None = None,
    agent_id: str | None = None,
    task_id: str | None = None,
    finding_id: str | None = None,
) -> Iterator[dict[str, str]]:
    """Bind correlation ids for the duration of a context.

    Only the explicitly provided ids are rebound; absent fields keep
    their current value. The :func:`current_correlation` snapshot is
    taken on entry and returned on exit so callers can echo it back
    to a client.
    """
    tokens: list[tuple[ContextVar[str], object]] = []
    if correlation_id is not None:
        tokens.append((_corr, _corr.set(correlation_id)))
    if campaign_id is not None:
        tokens.append((_camp, _camp.set(campaign_id)))
    if agent_id is not None:
        tokens.append((_agt, _agt.set(agent_id)))
    if task_id is not None:
        tokens.append((_tsk, _tsk.set(task_id)))
    if finding_id is not None:
        tokens.append((_find, _find.set(finding_id)))
    try:
        yield current_correlation()
    finally:
        for var, tok in reversed(tokens):
            var.reset(tok)  # type: ignore[arg-type]


def bind_structlog() -> None:
    """Bind the current correlation ids into structlog's contextvars."""
    import structlog

    cur = current_correlation()
    structlog.contextvars.bind_contextvars(
        correlation_id=cur["correlation_id"],
        campaign_id=cur["campaign_id"],
        agent_id=cur["agent_id"],
        task_id=cur["task_id"],
        finding_id=cur["finding_id"],
    )


def clear_structlog() -> None:
    import structlog

    structlog.contextvars.clear_contextvars()


__all__ = [
    "bind",
    "bind_structlog",
    "clear_structlog",
    "current_correlation",
    "new_correlation_id",
]
