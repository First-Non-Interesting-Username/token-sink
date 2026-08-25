"""Bearer token + localhost binding guards (spec §13).

- :class:`TokenAuth` is a FastAPI dependency that requires the
  ``Authorization: Bearer <token>`` header (or ``?token=`` query string
  for the SSE endpoint). Tokens are compared in constant time.
- :func:`enforce_localhost` checks the connected host and refuses to
  serve when the configured bind address is ``0.0.0.0`` or ``::``
  without the human-approved LAN flag. The check is purely
  configuration-driven; the actual ``uvicorn`` binding is configured
  by the CLI.
"""
from __future__ import annotations

import hmac
import ipaddress
import secrets
from dataclasses import dataclass

from fastapi import HTTPException, Request, status

# Tokens have a recognizable prefix so users can spot them in copy/paste.
TOKEN_PREFIX = "mavr_"


def new_bearer_token() -> str:
    """Generate a fresh, URL-safe bearer token with the MAVR prefix."""
    return f"{TOKEN_PREFIX}{secrets.token_urlsafe(24)}"


@dataclass(frozen=True)
class AuthContext:
    token: str


def _extract_token(request: Request) -> str | None:
    auth = request.headers.get("authorization") or request.headers.get("Authorization")
    if auth:
        parts = auth.split(None, 1)
        if len(parts) == 2 and parts[0].lower() == "bearer" and parts[1].strip():
            return parts[1].strip()
    q = request.query_params.get("token")
    if q:
        return q.strip()
    cookie = request.cookies.get("mavr_token")
    if cookie:
        return cookie.strip()
    return None


def require_bearer(expected: str):
    """Build a FastAPI dependency that requires ``expected`` as the token."""
    if not expected:
        raise RuntimeError("expected token is empty; refusing to install guard")
    expected_bytes = expected.encode("utf-8")

    def _dep(request: Request) -> AuthContext:
        provided = _extract_token(request)
        if not provided:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="missing bearer token",
                headers={"WWW-Authenticate": "Bearer"},
            )
        if not hmac.compare_digest(provided.encode("utf-8"), expected_bytes):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="invalid bearer token",
            )
        return AuthContext(token=provided)

    return _dep


def client_is_localhost(client_host: str | None) -> bool:
    """Return True if ``client_host`` resolves to a loopback address."""
    if not client_host:
        return False
    if client_host in {"127.0.0.1", "::1", "localhost"}:
        return True
    try:
        ip = ipaddress.ip_address(client_host.split("%")[0])
    except ValueError:
        return False
    return bool(ip.is_loopback)


def enforce_localhost(
    bind_host: str,
    *,
    allow_lan: bool,
    human_approved: bool,
    client_host: str | None,
) -> None:
    """Raise :class:`HTTPException` if the request must be refused.

    The bind host is what ``uvicorn`` is configured to listen on. If
    it's a wildcard (any address) the operator must have set
    ``--allow-lan --human-approved``. Once a wildcard bind is approved,
    non-loopback clients are also accepted.
    """
    wildcard = bind_host in {"0.0.0.0", "::", ""}
    if wildcard and not (allow_lan and human_approved):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="refusing to serve: LAN access requires --allow-lan --human-approved",
        )
    if not wildcard and not client_is_localhost(client_host):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="refusing to serve non-loopback clients",
        )


__all__ = [
    "AuthContext",
    "TOKEN_PREFIX",
    "client_is_localhost",
    "enforce_localhost",
    "new_bearer_token",
    "require_bearer",
]


# Useful type alias for endpoints that need the auth context. The real
# dependency is wired up in :mod:`mavr.api.app` so it can capture the
# bearer token; this alias exists for tests and external callers.
def BearerAuth() -> AuthContext:  # pragma: no cover - placeholder
    raise RuntimeError("use build_app() to install the real dependency")
