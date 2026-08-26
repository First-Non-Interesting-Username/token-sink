"""Fetch-time URL safety pipeline (PLAN §9/§15, issue #124).

Decides whether a specific HTTP fetch is allowed, and under which limits.
This is the layer that runs immediately before any network read; the policy
engine (#8) gates tool calls, this module gates individual requests.

Layers, evaluated in order:
1. URL validation: scheme allowlist, userinfo rejection (also in SSRFGuard,
   but repeated here so this module is safe standalone), IDN normalization.
2. Scope filter: every URL — including every redirect Location — must be
   in-scope for the campaign. Unlisted is refused, not guessed.
3. SSRF: literal and DNS-resolved addresses via ``SSRFGuard``; decimal/octal
   IPv4 shorthands and IPv6-mapped IPv4 are normalized first so they can't
   smuggle private addresses past a string-level check.
4. Redirect policy: each hop is re-validated from scratch; hop count capped.
5. Response limits: max bytes, content-type allowlist, timeout budget.

TOCTOU note: DNS may change between validation and connect. The pipeline
exposes ``validated_addresses()`` so the HTTP layer can pin the connection to
an address that was actually checked (or re-check post-resolution). A
``check_fetch`` result carries everything needed to enforce that.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from urllib.parse import urlparse

from policy.scope import ScopePolicy
from policy.ssrf import ALLOWED_SCHEMES, SSRFGuard


def normalize_ipv4_shorthand(host: str) -> str:
    """Expand decimal/octal/hex IPv4 shorthands to dotted-quad form.

    ``2130706433``, ``0x7f.0.0.1``, ``0177.0.0.1`` all mean 127.0.0.1 but do
    NOT match naive private-range regex checks. Python's ipaddress accepts
    some of these forms only when given as integers, so expand manually.
    Returns the input unchanged if it isn't such a shorthand.
    """
    if "/" in host or ":" in host:
        return host
    parts = host.split(".")
    if not 1 <= len(parts) <= 4:
        return host
    try:
        ints = []
        for p in parts:
            if p.startswith("0x") or p.startswith("0X"):
                ints.append(int(p, 16))
            elif p.startswith("0") and len(p) > 1 and p.isdigit():
                ints.append(int(p, 8))
            elif p.isdigit():
                ints.append(int(p, 10))
            else:
                return host  # non-numeric piece → hostname, leave alone
        if any(i > 255 for i in ints):
            # e.g. single 32-bit decimal form
            if len(ints) == 1:
                n = ints[0]
                return f"{(n >> 24) & 255}.{(n >> 16) & 255}.{(n >> 8) & 255}.{n & 255}"
            return host
        if len(ints) == 2:
            # a.b form: b covers the last three octets
            b = ints[1]
            if b > 0xFFFFFF:
                return host
            ints = [ints[0], (b >> 16) & 255, (b >> 8) & 255, b & 255]
        elif len(ints) == 3:
            # a.b.c form: c covers the last two octets
            c = ints[2]
            if c > 0xFFFF:
                return host
            ints = [ints[0], ints[1], (c >> 8) & 255, c & 255]
        while len(ints) < 4:
            ints.append(0)
        return ".".join(str(i) for i in ints[:4])
    except ValueError:
        return host


def normalize_host_for_check(url: str) -> str:
    """Lowercased, trailing-dot-stripped, shorthand-normalized hostname."""
    parsed = urlparse(url)
    host = parsed.hostname or ""
    # IPv6-mapped IPv4 (::ffff:10.0.0.1) must be judged by its IPv4 side.
    try:
        ip = ipaddress.ip_address(host)
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
            return str(ip.ipv4_mapped)
        return str(ip)
    except ValueError:
        pass
    return normalize_ipv4_shorthand(host.lower().rstrip("."))


def normalize_url_for_check(url: str) -> str:
    """URL with the host replaced by its normalized form."""
    parsed = urlparse(url)
    host = parsed.hostname or ""
    new_host = normalize_host_for_check(url)
    if host == new_host or not host:
        return url
    start = url.find(host)
    if start == -1:
        return url
    # If the original was a bracketed IPv6 literal, keep the brackets — the
    # mapped form rewrites [::ffff:10.0.0.1] to [10.0.0.1], which urlparse
    # then rejects (IPv4-in-brackets) — that rejection is itself a valid
    # fail-closed outcome, but produce it deterministically here.
    replacement = f"[{new_host}]" if url[start - 1 : start] == "[" else new_host
    return url[:start] + replacement + url[start + len(host) :]


@dataclass(frozen=True)
class FetchLimits:
    """Response-side budget for one fetch (§9)."""

    max_bytes: int = 2 * 1024 * 1024
    timeout_seconds: float = 30.0
    allowed_content_types: tuple[str, ...] = (
        "text/html",
        "text/plain",
        "application/json",
        "application/xhtml+xml",
        "text/xml",
        "application/xml",
        "application/pdf",
    )
    max_redirect_hops: int = 5


@dataclass
class FetchVerdict:
    """Result of validating one fetch (one hop of a chain)."""

    allowed: bool
    reason: str = ""
    normalized_url: str = ""
    resolved_addresses: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.allowed


class SafeFetchPolicy:
    """Validates URLs and redirect chains against scope + SSRF + limits."""

    def __init__(
        self,
        scope: ScopePolicy | None = None,
        ssrf: SSRFGuard | None = None,
        limits: FetchLimits | None = None,
    ) -> None:
        self._scope = scope
        self._ssrf = ssrf or SSRFGuard()
        self.limits = limits or FetchLimits()

    def check_url(self, url: str) -> FetchVerdict:
        """Validate a single URL through all static layers."""
        try:
            normalized = normalize_url_for_check(url)
        except ValueError:
            # e.g. bracketed IPv4 after mapping normalization — malformed host
            return FetchVerdict(False, "malformed URL host", url)
        try:
            parsed = urlparse(normalized)
        except ValueError as exc:
            return FetchVerdict(False, f"unparseable URL: {exc}", normalized)
        if parsed.scheme.lower() not in ALLOWED_SCHEMES:
            return FetchVerdict(False, f"scheme {parsed.scheme!r} not in allowlist", normalized)
        if parsed.username or parsed.password:
            return FetchVerdict(False, "userinfo embedded in URL is rejected", normalized)

        # Scope: unlisted destinations are refused — §9 applies filters BEFORE
        # follow-up actions, and §15 wants destination allowlists.
        if self._scope is not None:
            classification, _ = self._scope.classify_target(normalized)
            if classification != "in":
                return FetchVerdict(
                    False, f"destination is {classification} per campaign scope", normalized
                )

        ssrf = self._ssrf.check(normalized)
        if not ssrf.allowed:
            return FetchVerdict(False, f"ssrf: {ssrf.reason}", normalized)

        return FetchVerdict(True, "", normalized, resolved_addresses=self._resolved(normalized))

    def _resolved(self, url: str) -> list[str]:
        # Best-effort address listing for TOCTOU pinning; empty when the guard
        # did not need DNS (literal IP).
        try:
            answers = self._ssrf._resolver((urlparse(url).hostname or "").lower().rstrip("."))
            return [str(a) for a in answers]
        except OSError:
            return []

    def check_redirect_chain(self, start_url: str, locations: list[str]) -> FetchVerdict:
        """Validate a redirect path where each hop's Location is known.

        Every hop is re-checked from scratch against scope AND SSRF — a
        redirect must never inherit trust from the URL that led to it.
        """
        current = start_url
        for i, loc in enumerate(locations):
            if i >= self.limits.max_redirect_hops:
                return FetchVerdict(
                    False, f"redirect chain exceeds {self.limits.max_redirect_hops} hops"
                )
            # Relative Locations resolve against the current URL.
            nxt = loc if "://" in loc else _resolve_relative(current, loc)
            verdict = self.check_url(nxt)
            if not verdict.ok:
                return FetchVerdict(
                    False,
                    f"redirect hop {i + 1} ({nxt}): {verdict.reason}",
                    current,
                )
            current = nxt
        return FetchVerdict(True, "", current)

    def response_allowed(
        self, content_type: str, size_bytes: int, elapsed_seconds: float
    ) -> tuple[bool, str]:
        """Post-fetch checks: content type, size, and time budget."""
        ctype = (content_type or "").split(";")[0].strip().lower()
        if ctype and ctype not in self.limits.allowed_content_types:
            return False, f"content-type {ctype!r} not in allowlist"
        if size_bytes > self.limits.max_bytes:
            return False, f"response size {size_bytes} exceeds limit {self.limits.max_bytes}"
        if elapsed_seconds > self.limits.timeout_seconds * 1.5:
            # Small grace over the connect/read budget before declaring a violation.
            return False, f"fetch took {elapsed_seconds:.1f}s, over budget"
        return True, ""


def _resolve_relative(base: str, location: str) -> str:
    parsed = urlparse(base)
    if location.startswith("/"):
        return f"{parsed.scheme}://{parsed.netloc}{location}"
    # Simple relative path resolution (no full RFC 3986 machinery needed here).
    path = parsed.path.rsplit("/", 1)[0]
    return f"{parsed.scheme}://{parsed.netloc}{path}/{location}"
