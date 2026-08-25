"""Campaign scope model and target matching (PLAN §5).

A campaign carries an explicit, machine-checkable scope: in-scope targets,
explicit out-of-scope targets, allowed HTTP methods / test classes,
prohibited actions, and rate limits. The policy engine evaluates every tool
call against this scope before execution; missing or ambiguous scope is a
defined refusal state, never something agents guess around.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field


@dataclass(frozen=True)
class RateLimit:
    """Per-target request-rate ceiling (PLAN §5)."""

    max_requests: int
    per_seconds: float


@dataclass(frozen=True)
class TargetSpec:
    """One in-scope target: a domain (with optional subdomain wildcard),
    a URL prefix, a CIDR range, a repo/package/API/app identifier, or a
    single exact URL."""

    value: str
    kind: str = "auto"  # auto | domain | url | cidr | name

    def __post_init__(self) -> None:
        if self.kind not in ("auto", "domain", "url", "cidr", "name"):
            raise ValueError(f"unknown target kind: {self.kind!r}")

    def _resolved_kind(self) -> str:
        if self.kind != "auto":
            return self.kind
        v = self.value
        if "://" in v:
            return "url"
        try:
            ipaddress.ip_network(v, strict=False)
            return "cidr"
        except ValueError:
            pass
        if "/" in v or "@" in v or " " in v:
            return "name"
        return "domain"

    def matches_url(self, url: str) -> bool:
        """True when `url` falls inside this target.

        Domain targets match the host itself plus subdomains (a scope entry
        `example.com` covers `api.example.com`); scheme is not restricted at
        the target level — allowed schemes are a policy concern.
        """
        kind = self._resolved_kind()
        if kind == "name":
            # Repos/packages/APIs/apps are matched by explicit string
            # identity only — no fuzzy host matching.
            return url.strip() == self.value
        if kind == "url":
            return url.rstrip("/") == self.value.rstrip("/") or url.startswith(
                self.value.rstrip("/") + "/"
            )
        if kind == "cidr":
            from urllib.parse import urlparse

            try:
                host = urlparse(url).hostname or ""
                ip = ipaddress.ip_address(host)
            except ValueError:
                return False
            return ip in ipaddress.ip_network(self.value, strict=False)
        # domain
        from urllib.parse import urlparse

        host = (urlparse(url).hostname or "").lower().rstrip(".")
        target = self.value.lower().rstrip(".")
        return host == target or host.endswith("." + target)


@dataclass
class ScopePolicy:
    """The campaign scope surface evaluated by the policy engine (§5)."""

    campaign_uuid: str
    program_name: str = ""
    authorization_reference: str = ""
    in_scope: list[TargetSpec] = field(default_factory=list)
    out_of_scope: list[TargetSpec] = field(default_factory=list)
    allowed_methods: set[str] = field(default_factory=lambda: {"GET"})
    allowed_test_classes: set[str] = field(default_factory=set)
    prohibited_actions: set[str] = field(default_factory=set)
    active_testing_enabled: bool = False
    rate_limits: dict[str, RateLimit] = field(default_factory=dict)

    @staticmethod
    def _compile_patterns(patterns: list[str]) -> list[re.Pattern]:
        return [re.compile(p) for p in patterns]

    def classify_target(self, url_or_name: str) -> tuple[str, TargetSpec | None]:
        """Classify a destination as 'in', 'out', or 'unlisted'.

        Explicit out-of-scope entries always win over in-scope matches — an
        admin carving one path out of a wildcard must not be overridden.
        """
        for t in self.out_of_scope:
            if t.matches_url(url_or_name):
                return "out", t
        for t in self.in_scope:
            if t.matches_url(url_or_name):
                return "in", t
        return "unlisted", None


# Test classes that are considered active testing (mutating/probing the
# target rather than reading public pages). Gated behind
# `active_testing_enabled` plus human approval requirements handled upstream.
ACTIVE_TEST_CLASSES = frozenset(
    {
        "vulnerability_scanning",
        "exploit_verification",
        "poc_execution",
        "fuzzing",
        "brute_force",
        "injection_testing",
    }
)

# Actions that are always prohibited regardless of campaign configuration —
# the PLAN §5 examples are hard-blocked, not configurable away.
HARD_PROHIBITED_ACTIONS = frozenset(
    {
        "denial_of_service",
        "destructive_mutation",
        "spam",
        "credential_attacks",
        "data_exfiltration",
    }
)
