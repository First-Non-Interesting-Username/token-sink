"""URL scope filter (PLAN §9): the chokepoint gating every follow-up action
on a discovered URL.

Given a URL — or a whole redirect chain — classify it as in-scope,
out-of-scope, or ambiguous, with a reason. The search/extraction subsystems
(#18/#19) must call this BEFORE any fetch; the policy engine (#8) uses the
same classification for tool-call gating.

Design points:
- Every hop of a redirect chain is re-checked: an in-scope page redirecting
  to an out-of-scope or private host is blocked (SSRF interplay, #26).
- Ambiguous scope is a defined refusal state (§5), not a guess.
- Hardened against lookalike-host tricks: IDN/punycode homoglyphs are decoded
  before matching, trailing-dot FQDNs and case variations normalize away,
  userinfo (`user@host`) can never smuggle a host past the classifier.
"""

from __future__ import annotations

import enum
import ipaddress
from dataclasses import dataclass
from urllib.parse import urlparse

# Schemes that may ever be followed. Everything else is refused outright —
# allowlist, not blocklist, per §15. javascript:/data:/file: URLs have no
# legitimate place in a research fetch pipeline.
ALLOWED_SCHEMES = frozenset({"http", "https"})


class ScopeVerdict(enum.Enum):
    IN_SCOPE = "in_scope"
    OUT_OF_SCOPE = "out_of_scope"
    AMBIGUOUS = "ambiguous"


@dataclass(frozen=True)
class Classification:
    verdict: ScopeVerdict
    reason: str
    url: str
    hop_index: int = 0  # which redirect hop failed (0 = original URL)


def _punycode_decode(host: str) -> str:
    """Decode IDN/punycode labels so `xn--pple-43d.com` compares as its real
    Unicode form against the scope entry — and so a scope entry written in
    Unicode matches its punycode wire form on the wire."""
    if not host.startswith("xn--") and ".xn--" not in host:
        return host
    try:
        return host.encode("ascii").decode("idna")
    except UnicodeError:
        # Malformed punycode: fail closed — treat as-is; it will simply not
        # match any in-scope entry.
        return host


def _normalize_host(url: str) -> str:
    """Canonical host extraction: lowercase, strip one trailing dot (a
    fully-qualified `example.com.` IS example.com), decode punycode, reject
    userinfo smuggling by taking only the true hostname component."""
    parsed = urlparse(url)
    host = parsed.hostname or ""
    return _punycode_decode(host.lower().rstrip("."))


def _normalize_url(url: str) -> str:
    """Scheme/host normalized for prefix comparison: lowercase scheme+host,
    strip default ports, drop the trailing-dot FQDN quirk, drop fragment."""
    parsed = urlparse(url)
    scheme = parsed.scheme.lower()
    host = _normalize_host(url)

    # Reject userinfo up front: `https://trusted.example.com@evil.com/` has
    # hostname evil.com, but the visual trick deserves its own refusal reason.
    if parsed.username or parsed.password:
        return url  # caller refuses via _classify_single before this matters

    port = parsed.port
    default = {"http": 80, "https": 443}.get(scheme)
    netloc = host if port in (None, default) else f"{host}:{port}"
    path = parsed.path or "/"
    return f"{scheme}://{netloc}{path}"


class UrlScopeFilter:
    """Classifies URLs against a campaign's scope lists.

    `in_scope` entries may be domains (`example.com` — includes subdomains),
    URL prefixes (`https://api.example.com/v2`), or exact URLs. CIDR ranges
    are supported for IP-literal targets. `out_of_scope` always wins.
    """

    def __init__(
        self,
        in_scope: list[str],
        out_of_scope: list[str] | None = None,
        *,
        allowed_schemes: frozenset[str] | None = None,
    ):
        self.in_scope = list(in_scope)
        self.out_of_scope = list(out_of_scope or [])
        self.allowed_schemes = allowed_schemes or ALLOWED_SCHEMES

    # -- single URL ---------------------------------------------------------

    def check(self, url: str) -> Classification:
        return self._check_hop(url, hop=0)

    def _check_hop(self, url: str, *, hop: int) -> Classification:
        try:
            parsed = urlparse(url)
        except ValueError as exc:
            return Classification(ScopeVerdict.AMBIGUOUS, f"unparseable URL: {exc}", url, hop)

        if parsed.scheme.lower() not in self.allowed_schemes:
            return Classification(
                ScopeVerdict.OUT_OF_SCOPE,
                f"scheme {parsed.scheme!r} is not allowed "
                f"(allowed: {sorted(self.allowed_schemes)})",
                url,
                hop,
            )

        if parsed.username or parsed.password:
            return Classification(
                ScopeVerdict.OUT_OF_SCOPE,
                "URL embeds credentials (userinfo) — refused to prevent "
                "`https://in.scope@evil.host/` style confusion",
                url,
                hop,
            )

        host = _normalize_host(url)
        if not host:
            return Classification(ScopeVerdict.AMBIGUOUS, "URL has no hostname", url, hop)

        # Literal IP hosts: match against CIDR scope entries only.
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            ip = None

        out = self._match_list(self.out_of_scope, url, host, ip)
        if out:
            return Classification(
                ScopeVerdict.OUT_OF_SCOPE,
                f"explicitly out of scope (matches {out.value!r})",
                url,
                hop,
            )

        inn = self._match_list(self.in_scope, url, host, ip)
        if inn:
            return Classification(
                ScopeVerdict.IN_SCOPE, f"in scope (matches {inn.value!r})", url, hop
            )

        # Default-deny: anything unlisted is refused with an actionable
        # explanation rather than guessed about (§5).
        return Classification(
            ScopeVerdict.AMBIGUOUS,
            "not listed in campaign scope — add it explicitly or drop the URL (default-deny)",
            url,
            hop,
        )

    def _match_list(self, entries: list[str], url: str, host: str, ip):
        for raw in entries:
            spec = _ScopeEntry.parse(raw)
            if spec.matches(host, url, ip):
                return spec
        return None

    # -- redirect chains ------------------------------------------------------

    def check_redirect_chain(
        self, urls: list[str], *, private_ip_hosts: frozenset[str] = frozenset()
    ) -> Classification:
        """Check every hop of a redirect chain; the first failure wins.

        `private_ip_hosts` lets callers flag hosts they observed resolving to
        private addresses (DNS-rebinding defense, interplay with #26): a hop
        to such a host is blocked even if the name itself looks in-scope.
        """
        if not urls:
            return Classification(ScopeVerdict.AMBIGUOUS, "empty redirect chain", "", 0)
        for i, url in enumerate(urls):
            verdict = self._check_hop(url, hop=i)
            if verdict.verdict is not ScopeVerdict.IN_SCOPE:
                return verdict
            host = _normalize_host(url)
            if host in private_ip_hosts:
                return Classification(
                    ScopeVerdict.OUT_OF_SCOPE,
                    f"{host} resolved to a private address (rebinding risk); "
                    "redirect chain blocked",
                    url,
                    i,
                )
        return Classification(
            ScopeVerdict.IN_SCOPE,
            f"all {len(urls)} hops in scope",
            urls[-1],
            len(urls) - 1,
        )


@dataclass(frozen=True)
class _ScopeEntry:
    """One parsed scope entry: domain, URL prefix, exact URL, or CIDR."""

    value: str
    kind: str  # domain | url_prefix | cidr
    host: str = ""
    path: str = ""

    @staticmethod
    def parse(raw: str) -> _ScopeEntry:
        value = raw.strip()
        if "/" in value and "://" not in value:
            # Looks like a bare CIDR (e.g. 10.0.0.0/8).
            try:
                ipaddress.ip_network(value, strict=False)
                return _ScopeEntry(value, "cidr")
            except ValueError:
                pass
        if "://" in value:
            parsed = urlparse(value)
            host = _punycode_decode((parsed.hostname or "").lower().rstrip("."))
            path = parsed.path.rstrip("/")
            return _ScopeEntry(value, "url_prefix", host=host, path=path)
        return _ScopeEntry(value, "domain", host=_punycode_decode(value.lower().rstrip(".")))

    def matches(
        self,
        host: str,
        url: str,
        ip,  # ip: IPv4Address | IPv6Address | None
    ) -> bool:
        if self.kind == "cidr":
            if ip is None:
                return False
            try:
                return ip in ipaddress.ip_network(self.value, strict=False)
            except ValueError:
                return False
        if self.kind == "url_prefix":
            norm = _normalize_url(url)
            base = self._normalized_base()
            return norm == base or norm.startswith(base + "/")
        # domain: exact host or any subdomain
        return host == self.host or host.endswith("." + self.host)

    def _normalized_base(self) -> str:
        parsed = urlparse(self.value)
        scheme = parsed.scheme.lower()
        port = parsed.port
        default = {"http": 80, "https": 443}.get(scheme)
        host = _normalize_host(self.value)
        netloc = host if port in (None, default) else f"{host}:{port}"
        path = (parsed.path or "").rstrip("/")
        return f"{scheme}://{netloc}{path}"
