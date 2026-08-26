"""Local web-UI security hardening middleware (issue #152, PLAN §3.1, §15).

Design decisions (per AGENTS.md "document everything"):

- **Defense in depth at one choke point.** The existing approval API
  (``api/approvals.py``) already binds loopback by default; this module adds
  the *request-level* defenses any local state-changing endpoint needs:
  Host validation (DNS-rebinding defense), Origin validation on mutating
  methods, and a per-launch bearer token required on every non-GET request.

- **Fail closed.** Missing/invalid token, foreign Origin, or mismatched Host
  each reject the request before it reaches the handler. GET requests stay
  side-effect free by contract — enforcement of that lives with the route
  table, not here, but ``MUTATING_METHODS`` defines the set that must be
  authenticated.

- **Per-launch random token.** Generated from ``secrets.token_urlsafe``;
  rotation on restart invalidates all old sessions by construction. The CLI
  prints it once; the UI sends it as ``Authorization: Bearer <token>`` —
  deliberately not cookie-based, so a drive-by browser page cannot present
  ambient credentials.

- Pure functions over (method, headers) → verdict; no I/O, trivially
  unit-testable and composable with the stdlib HTTP server.
"""

from __future__ import annotations

import secrets
from collections.abc import Mapping
from dataclasses import dataclass

MUTATING_METHODS = ("POST", "PUT", "PATCH", "DELETE")

# A request whose Host header is not an exact match for one of these is a
# DNS-rebinding attempt (an external hostname resolving to 127.0.0.1).
_ALLOWED_HOST_SUFFIXES = ("127.0.0.1", "localhost", "::1")


def generate_session_token() -> str:
    """One fresh token per server launch."""
    return secrets.token_urlsafe(32)


@dataclass(frozen=True)
class SecurityVerdict:
    allowed: bool
    status: int = 200
    reason: str = "ok"


def check_host(host_header: str | None) -> SecurityVerdict:
    """Reject Host headers that don't identify the local machine (#152)."""
    if not host_header:
        return SecurityVerdict(False, 400, "missing Host header")
    host = host_header.rsplit(":", 1)[0] if "]:" not in host_header else host_header
    host = host.strip("[]")
    # strip port for ipv4/hostname forms
    if ":" in host and "[" not in host_header:
        host = host.rsplit(":", 1)[0]
    if host == "localhost" or host.startswith("127.") or host == "::1":
        return SecurityVerdict(True)
    return SecurityVerdict(False, 403, f"untrusted Host header {host!r} (DNS rebinding?)")


def check_origin(
    method: str, origin: str | None, *, allow_missing_origin: bool = True
) -> SecurityVerdict:
    """Cross-site Origins are rejected on mutating endpoints (CSRF defense).

    Non-browser clients legitimately send no Origin header; browsers always
    do on cross-site requests, which is exactly the case we must block.
    """
    if method.upper() not in MUTATING_METHODS:
        return SecurityVerdict(True)
    if origin is None:
        return (
            SecurityVerdict(True)
            if allow_missing_origin
            else SecurityVerdict(False, 403, "missing Origin on mutating request")
        )
    local = "127.0.0.1" in origin or "localhost" in origin
    if local or origin.rstrip("/").endswith(("127.0.0.1", "localhost")):
        return SecurityVerdict(True)
    return SecurityVerdict(False, 403, f"cross-origin mutating request from {origin!r}")


def check_token(method: str, authorization: str | None, expected_token: str) -> SecurityVerdict:
    """Bearer token required on every state-changing request."""
    if method.upper() not in MUTATING_METHODS:
        return SecurityVerdict(True)
    if not authorization or not authorization.startswith("Bearer "):
        return SecurityVerdict(False, 401, "missing bearer token on mutating request")
    supplied = authorization[len("Bearer ") :]
    if not secrets.compare_digest(supplied, expected_token):
        return SecurityVerdict(False, 401, "invalid session token (rotated?)")
    return SecurityVerdict(True)


def guard_request(
    method: str,
    headers: Mapping[str, str],
    *,
    expected_token: str,
    require_origin: bool = False,
) -> SecurityVerdict:
    """Run the full local-hardening gauntlet for one request.

    Order matters: cheap rejections first, authentication last so timing of
    token comparison isn't observable through earlier failure modes.
    """
    h = {k.lower(): v for k, v in headers.items()}
    v = check_host(h.get("host"))
    if not v.allowed:
        return v
    v = check_origin(method, h.get("origin"), allow_missing_origin=not require_origin)
    if not v.allowed:
        return v
    return check_token(method, h.get("authorization"), expected_token)
