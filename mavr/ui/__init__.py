"""UI module: Jinja templates + static assets used by the API layer.

The actual rendering is wired by :mod:`mavr.api.app` via FastAPI's
:class:`Jinja2Templates` and :class:`StaticFiles` mount. This package
just makes the static paths discoverable.
"""
from __future__ import annotations

from mavr.api.app import STATIC_DIR, TEMPLATES_DIR, UI_DIR

__all__ = ["STATIC_DIR", "TEMPLATES_DIR", "UI_DIR"]
