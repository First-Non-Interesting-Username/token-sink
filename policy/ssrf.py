"""SSRF protections (PLAN §9/§15): block local, private, link-local, and
cloud-metadata destinations unless explicitly authorized by campaign scope.

Checks happen both on literal hostnames/IPs and on resolved DNS answers so a
public-looking hostname that resolves to a private address (DNS-rebinding
style) is still caught.
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import urlparse

# Schemes the tool may ever speak. Everything else (file:, gopher:, ftp:, …)
# is rejected outright — allowlist, not blocklist, per §15.
ALLOWED_SCHEMES = frozenset({"http", "https"})

METADATA_HOSTS = frozenset({"metadata.google.internal", "instance-data", "metadata"})


def _is_private_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    # is_private alone misses some cases we care about (e.g. it treats the
    # documentation ranges as private but not 0.0.0.0), so enumerate explicitly.
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


@dataclass(frozen=True)
class SSRFVerdict:
    allowed: bool
    reason: str


class SSRFGuard:
    """Evaluates URLs for server-side-request-forgery risk."""

    def __init__(self, resolver=None):
        # Injectable resolver keeps tests hermetic (no real DNS).
        self._resolver = resolver or (
            lambda host: [ai[4][0] for ai in socket.getaddrinfo(host, None)]
        )

    def check(self, url: str, *, private_network_authorized: bool = False) -> SSRFVerdict:
        try:
            parsed = urlparse(url)
        except ValueError as exc:
            return SSRFVerdict(False, f"unparseable URL: {exc}")

        if parsed.scheme.lower() not in ALLOWED_SCHEMES:
            return SSRFVerdict(False, f"URL scheme {parsed.scheme!r} is not allowed")

        host = parsed.hostname or ""
        if not host:
            return SSRFVerdict(False, "URL has no hostname")
        host_l = host.lower().rstrip(".")

        # Credentials embedded in URLs leak secrets into logs/targets.
        if parsed.username or parsed.password:
            return SSRFVerdict(False, "URLs with embedded credentials are not allowed")

        if host_l in METADATA_HOSTS:
            return SSRFVerdict(False, "cloud metadata service is blocked")

        # Literal IPs: decide without touching DNS.
        try:
            ip = ipaddress.ip_address(host_l)
        except ValueError:
            ip = None
        else:
            if _is_private_ip(ip) and not private_network_authorized:
                return SSRFVerdict(False, f"private/loopback/link-local address {ip} is blocked")
            return SSRFVerdict(True, "")

        if private_network_authorized:
            return SSRFVerdict(True, "")

        # Hostname: resolve and inspect every answer. A name with ANY private
        # resolution is treated as private (fail closed).
        try:
            answers = self._resolver(host_l)
        except OSError as exc:
            return SSRFVerdict(False, f"DNS resolution failed: {exc}")
        if not answers:
            return SSRFVerdict(False, "hostname did not resolve")
        for answer in answers:
            try:
                ip = ipaddress.ip_address(answer)
            except ValueError:
                continue
            if _is_private_ip(ip):
                return SSRFVerdict(
                    False,
                    f"{host_l} resolves to private/loopback/link-local address "
                    f"{ip} (possible rebinding)",
                )
        return SSRFVerdict(True, "")
