"""robots.txt & ToS-aware fetching policy layer (issue #300, PLAN §9/§15).

Decides whether a URL may be fetched for a given purpose, honoring:

- **robots.txt** — fetched once per host, cached with a TTL, evaluated with
  the stdlib ``urllib.robotparser``. A host whose robots.txt is unreachable
  is treated conservatively: 4xx (no robots) ⇒ allow (per RFC 9309), but
  5xx/unparseable ⇒ deny, because a server erroring on robots may also be
  stressed by our traffic — politeness beats access.
- **ToS restrictions** — per-target operator-entered flags (e.g.
  ``no_automated_fetch``) that tighten robots rather than loosen them.

This layer composes with ``search.safe_fetch`` (SSRF/scheme/response
limits) and ``policy.url_filter`` (scope allowlist): it answers only the
politeness/permission question and returns a decision record that can go
straight into the audit trail. It can never *grant* something another
layer denied — callers must still run those checks.

Deny-by-default applies to the uncertain cases; an explicit
``authorized_override=True`` (recorded in the decision) lets operators
fetch from targets they are contractually authorized to test even when
robots disallows — this is a security-research tool and authorization is
the whole point of its scope model.
"""

from __future__ import annotations

import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from urllib import robotparser
from urllib.parse import urlparse

DEFAULT_ROBOTS_TTL_SECONDS = 3600.0
DEFAULT_FETCH_UA = "token-sink-agent"


@dataclass(frozen=True)
class FetchPermission:
    """One politeness-layer decision, audit-ready."""

    url: str
    allowed: bool
    reason: str
    source: str  # "robots_allow" | "robots_disallow" | "tos" | "conservative_deny" | "override"
    override_used: bool = False


@dataclass
class TosPolicy:
    """Operator-entered target restrictions; only ever tightens."""

    no_automated_fetch: bool = False
    allowed_purposes: set[str] | None = None  # None = all purposes OK
    notes: str = ""


class RobotsCache:
    """Per-host robots.txt with TTL; injectable loader for tests."""

    def __init__(
        self,
        ttl_seconds: float = DEFAULT_ROBOTS_TTL_SECONDS,
        loader=None,
        clock=time.monotonic,
        user_agent: str = DEFAULT_FETCH_UA,
    ):
        self.ttl = ttl_seconds
        self._loader = loader or _default_loader
        self._clock = clock
        self._ua = user_agent
        self._cache: dict[str, tuple[float, robotparser.RobotFileParser | None]] = {}

    def get(self, host: str) -> robotparser.RobotFileParser | None:
        """Return a parsed parser, or a synthetic parser when robots.txt is
        unavailable. ``synthetic="deny"`` on the result marks fail-closed
        (5xx/unparseable); plain ``None``-equivalent availability is expressed
        as a permissive empty parser so callers have one interface."""
        now = self._clock()
        if host in self._cache and now - self._cache[host][0] < self.ttl:
            return self._cache[host][1]
        status, _body, lines = self._loader(host)
        if status == 200:
            rp = robotparser.RobotFileParser()
            rp.parse(lines)
            rp.synthetic = "none"
        elif 400 <= status < 500:
            # RFC 9309: unavailable-by-config (4xx) means unrestricted crawl.
            rp = robotparser.RobotFileParser()
            rp.parse([])
            rp.synthetic = "permissive"
        else:
            # 5xx / network garbage: fail closed — see module docstring.
            rp = robotparser.RobotFileParser()
            rp.parse(["User-agent: *", "Disallow: /"])
            rp.synthetic = "deny"
        self._cache[host] = (now, rp)
        return rp


class FetchPolicy:
    """Composes robots.txt + ToS flags into one fetch permission."""

    def __init__(
        self,
        robots: RobotsCache | None = None,
        tos_by_host: dict[str, TosPolicy] | None = None,
        user_agent: str = DEFAULT_FETCH_UA,
    ):
        self.robots = robots or RobotsCache()
        self.tos = tos_by_host or {}
        self.user_agent = user_agent

    def check(
        self, url: str, purpose: str = "search", authorized_override: bool = False
    ) -> FetchPermission:
        host = urlparse(url).hostname or ""
        if not host:
            return FetchPermission(url, False, "URL has no hostname", "conservative_deny")

        # ToS first: operator-entered restrictions outrank robots parsing and
        # can never be overridden by authorization claims alone... except the
        # explicit override flag, which exists precisely for authorized targets.
        tos = self.tos.get(host)
        if tos and tos.no_automated_fetch:
            if authorized_override:
                # ToS override is itself a recorded decision — the operator
                # vouches for contractual authorization on this target.
                pass  # fall through; final record marks the override
            else:
                return FetchPermission(url, False, f"{host} ToS forbids automated fetch", "tos")

        rp = self.robots.get(host)
        if getattr(rp, "synthetic", "") == "deny":
            if authorized_override:
                return FetchPermission(
                    url,
                    True,
                    "robots unavailable — authorized override",
                    "override",
                    override_used=True,
                )
            return FetchPermission(
                url,
                False,
                "robots.txt unreachable (server error) — denied until it responds",
                "conservative_deny",
            )

        allowed = rp is not None and rp.can_fetch(self.user_agent, url) and rp.can_fetch("*", url)
        if not allowed:
            if authorized_override:
                return FetchPermission(
                    url,
                    True,
                    "robots disallows — authorized override",
                    "override",
                    override_used=True,
                )
            return FetchPermission(url, False, "robots.txt disallows this path", "robots_disallow")

        # Purpose restriction is ToS-level, checked after robots so both
        # constraints apply (a path may be robots-allowed but purpose-barred).
        if tos and tos.allowed_purposes is not None and purpose not in tos.allowed_purposes:
            return FetchPermission(
                url, False, f"purpose '{purpose}' not permitted by {host} ToS", "tos"
            )
        if authorized_override:
            # The override flag was set (robots/ToS would otherwise gate this
            # fetch) — mark it so the audit trail shows a vouched decision.
            return FetchPermission(
                url, True, "allowed under authorized override", "override", override_used=True
            )
        return FetchPermission(url, True, "allowed by robots.txt and ToS", "robots_allow")


def _default_loader(host: str) -> tuple[int, bytes | None, list[str]]:
    """Fetch https://host/robots.txt; returns (status, body, text_lines)."""
    try:
        req = urllib.request.Request(
            f"https://{host}/robots.txt",
            headers={"User-Agent": DEFAULT_FETCH_UA},
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = resp.read(512 * 1024)
            return resp.status, body, body.decode("utf-8", errors="replace").splitlines()
    except urllib.error.HTTPError as exc:
        return exc.code, None, []
    except Exception:
        return 599, None, []  # network failure → conservative deny


def _make_permissive() -> robotparser.RobotFileParser:
    rp = robotparser.RobotFileParser()
    rp.parse([])
    return rp


def _make_deny_all() -> robotparser.RobotFileParser:
    rp = robotparser.RobotFileParser()
    rp.parse(["User-agent: *", "Disallow: /"])
    return rp
