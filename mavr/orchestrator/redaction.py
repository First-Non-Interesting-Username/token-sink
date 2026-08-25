"""Secret redaction for quarantine logs and audit metadata.

The runtime must never persist raw secrets, tokens, passwords, or API
keys when recording a task's inputs for later inspection. The
:func:`redact` helper takes a nested mapping/list/scalar structure and
returns a copy with sensitive values replaced by a sentinel.
"""
from __future__ import annotations

from typing import Any, Final

REDACTED: Final[str] = "***REDACTED***"

# Lower-cased substring matches. Conservative: matches on partial keys
# (e.g. ``api_token`` -> redacted).
_SENSITIVE_KEYS: Final[tuple[str, ...]] = (
    "secret",
    "password",
    "passwd",
    "token",
    "access_token",
    "refresh_token",
    "id_token",
    "jwt",
    "bearer",
    "api_key",
    "apikey",
    "authorization",
    "auth_header",
    "cookie",
    "session",
    "private_key",
    "client_secret",
)

_MAX_DEPTH: Final[int] = 32


def _is_sensitive(key: str | None) -> bool:
    if not key:
        return False
    lk = key.lower()
    return any(s in lk for s in _SENSITIVE_KEYS)


def redact(value: Any, *, _key: str | None = None, _depth: int = 0) -> Any:
    """Return a copy of ``value`` with secrets masked."""
    if _depth > _MAX_DEPTH:
        return REDACTED
    if _is_sensitive(_key):
        return REDACTED
    if isinstance(value, dict):
        return {k: redact(v, _key=str(k), _depth=_depth + 1) for k, v in value.items()}
    if isinstance(value, list | tuple):
        redacted_list = [redact(v, _key=_key, _depth=_depth + 1) for v in value]
        return type(value)(redacted_list) if isinstance(value, tuple) else redacted_list
    return value
