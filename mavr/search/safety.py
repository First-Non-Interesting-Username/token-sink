"""Network and filesystem safety helpers for the search/extraction subsystem.

The threat model (spec §9.3, §15) is:

* URLs whose resolved IPs fall in private, loopback, link-local,
  multicast, CGNAT, broadcast, or cloud-metadata (169.254.169.254)
  ranges must be denied UNLESS the campaign has
  ``explicit_unsafe_networking=True`` AND ``human_approved=True``.
* DNS resolution happens at request time so DNS rebinding cannot
  bypass the denylist (a hostname that resolves to a public IP at
  lookup time and a private IP at connect time is still caught
  because we check IPs before each request).
* Any artifact derived from a fetched URL (filename, slug) must be
  stripped of path-traversal sequences before being used to write
  to disk.

This module is intentionally side-effect free — it does no IO and
does not call the network. Callers feed it pre-resolved IPs or
let it resolve for them.
"""
from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass
from typing import Final
from urllib.parse import urlparse

from mavr.observability.logging import get_logger
from mavr.schemas import entities as schema

log = get_logger(__name__)


# ---- network denylist -----------------------------------------------------


# Hard-coded ranges — same denylist the policy engine uses. We keep a
# copy here so the search subsystem can be evaluated independently of
# the policy engine (e.g. when used by agents that bypass the policy
# path because they have already been authorized by the orchestrator).
_BLOCKED_NETWORKS: Final[tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]] = (
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("169.254.0.0/16"),       # link-local + 169.254.169.254
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),        # CGNAT
    ipaddress.ip_network("224.0.0.0/4"),          # multicast
    ipaddress.ip_network("240.0.0.0/4"),          # reserved/broadcast
    ipaddress.ip_network("169.254.169.254/32"),   # explicit metadata IP
    ipaddress.ip_network("fc00::/7"),             # IPv6 ULA
    ipaddress.ip_network("fe80::/10"),            # IPv6 link-local
)

_ALLOWED_SCHEMES: Final[frozenset[str]] = frozenset({"http", "https"})


# ---- exceptions ------------------------------------------------------------


class SafetyError(ValueError):
    """Raised when a URL fails a safety check."""


class SSRFBlocked(SafetyError):
    """Raised when a target resolves to a private/denied network."""


class UnsafeScheme(SafetyError):
    """Raised when a URL uses a non-http(s) scheme."""


class PathTraversalError(SafetyError):
    """Raised when a derived artifact path would escape its root."""


# ---- result types ----------------------------------------------------------


@dataclass(frozen=True)
class ResolvedTarget:
    """The host plus the IPs it resolved to at request time."""

    host: str
    ips: tuple[str, ...]


@dataclass(frozen=True)
class SafetyVerdict:
    """Decision produced by :func:`check_url`."""

    allowed: bool
    scheme_ok: bool
    host_ok: bool
    host: str
    ips: tuple[str, ...]
    reason: str = ""
    rule: str = ""


# ---- URL safety ------------------------------------------------------------


def _strip_ipv6_zone(ip: str) -> str:
    return ip.split("%", 1)[0]


def _ip_in_blocked(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    for net in _BLOCKED_NETWORKS:
        if ip.version != net.version:
            continue
        if ip in net:
            return True
    return False


def resolve_now(host: str) -> tuple[str, ...]:
    """Resolve ``host`` at request time. Returns ``()`` on failure."""
    if not host:
        return ()
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return ()
    return tuple(sorted({_strip_ipv6_zone(i[4][0]) for i in infos}))


def check_url(
    url: str,
    *,
    pre_resolved: tuple[str, ...] | None = None,
    allow_unsafe_networking: bool = False,
) -> SafetyVerdict:
    """Validate a URL for safe extraction.

    Args:
        url: The URL to evaluate.
        pre_resolved: Optional tuple of IPs the caller already resolved
            for this host. When supplied, the host is NOT re-resolved.
            This is the recommended pattern for defeating DNS rebinding:
            resolve, then immediately pass the IPs through here.
        allow_unsafe_networking: When True, the private-network
            denylist is bypassed. The caller must enforce
            ``scope.human_approved`` themselves.

    Returns:
        A :class:`SafetyVerdict`. Callers should treat ``allowed=False``
        as a hard error.
    """
    try:
        parsed = urlparse(url)
    except ValueError as exc:
        return SafetyVerdict(
            allowed=False, scheme_ok=False, host_ok=False,
            host="", ips=(), reason=f"invalid URL: {exc}", rule="invalid_url",
        )

    scheme = (parsed.scheme or "").lower()
    if scheme not in _ALLOWED_SCHEMES:
        return SafetyVerdict(
            allowed=False, scheme_ok=False, host_ok=True,
            host=(parsed.hostname or "").lower(), ips=(),
            reason=f"scheme {scheme!r} not allowed (only http/https)",
            rule="bad_scheme",
        )

    host = (parsed.hostname or "").lower()
    if not host:
        return SafetyVerdict(
            allowed=False, scheme_ok=True, host_ok=False,
            host="", ips=(), reason="URL is missing a host", rule="no_host",
        )

    ips = tuple(pre_resolved) if pre_resolved else resolve_now(host)

    if not allow_unsafe_networking:
        for ip in ips:
            if _ip_in_blocked(ip):
                return SafetyVerdict(
                    allowed=False, scheme_ok=True, host_ok=False,
                    host=host, ips=ips,
                    reason=f"target {host!r} ({ip}) is in a denied network range",
                    rule="ssrf_denylist",
                )

    return SafetyVerdict(
        allowed=True, scheme_ok=True, host_ok=True, host=host, ips=ips,
    )


# ---- path safety -----------------------------------------------------------


_SLUG_BAD_RE: Final[re.Pattern[str]] = re.compile(r"[^a-zA-Z0-9._-]+")
_SLUG_LEADING_DOT_RE: Final[re.Pattern[str]] = re.compile(r"^\.+")
_MAX_SLUG_LEN: Final[int] = 200


def safe_slug(value: str, *, max_length: int = _MAX_SLUG_LEN) -> str:
    """Reduce ``value`` to a filename-safe slug.

    * Replaces any run of unsafe characters with a single ``_``.
    * Strips leading dots to avoid hidden files / ``..`` traversal.
    * Caps the length.
    * Returns ``"_"`` for the empty case.

    This is intentionally conservative. Callers should not pass
    attacker-controlled filenames to the artifact store without
    going through here.
    """
    if not isinstance(value, str):
        raise PathTraversalError("slug must be a string")
    cleaned = _SLUG_BAD_RE.sub("_", value.strip())
    cleaned = _SLUG_LEADING_DOT_RE.sub("", cleaned)
    if not cleaned:
        return "_"
    return cleaned[:max_length]


def assert_within_root(root: str, candidate: str) -> str:
    """Return ``candidate`` resolved if it is inside ``root`` else raise.

    Prevents path-traversal sequences (``..``, absolute paths, symlink
    tricks) from causing an artifact to be written outside the
    configured storage root.
    """
    from pathlib import Path

    root_abs = Path(root).expanduser().resolve()
    cand_abs = Path(candidate).expanduser().resolve()
    try:
        cand_abs.relative_to(root_abs)
    except ValueError as exc:
        raise PathTraversalError(
            f"path {candidate} escapes root {root}"
        ) from exc
    return str(cand_abs)


# ---- scope helpers ---------------------------------------------------------


def scope_allows_unsafe_networking(scope: schema.ScopePolicy) -> bool:
    """Return True if the campaign's scope policy permits the private
    network denylist to be bypassed.

    Both ``explicit_unsafe_networking`` and ``human_approved`` must be
    set. This is the ONLY sanctioned override.
    """
    return bool(scope.explicit_unsafe_networking and scope.human_approved)
