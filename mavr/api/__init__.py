"""Local web API and UI (spec §13, §14).

The :class:`App` is a thin FastAPI wrapper that:

- Exposes REST endpoints for every CLI action.
- Serves a Jinja + htmx single-page UI.
- Streams system events through Server-Sent Events at ``/api/events``.
- Enforces a localhost-only bearer token. ``0.0.0.0`` binding requires
  the ``--allow-lan`` flag plus an explicit human-approval flag.
- Centralizes an :class:`AppState` so all subsystems share a single
  database, event bus, metrics store, and approval gate.
"""
from __future__ import annotations

from mavr.api.app import App, AppState, build_app

__all__ = ["App", "AppState", "build_app"]
