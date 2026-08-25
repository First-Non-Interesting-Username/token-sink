"""Scope policy engine.

Given a campaign + tool call (URL, method, action class, payload summary),
returns ``allow`` / ``deny`` / ``quarantine`` with a reason.

Hard-coded SSRF denylist (loopback, link-local, RFC1918, multicast,
cloud metadata) applies UNLESS the campaign has both
``explicit_unsafe_networking=True`` AND ``human_approved=True``. The
denylist is enforced at the policy layer, with DNS resolution done at
request time so DNS rebinding cannot bypass it.
"""
from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass
from enum import Enum
from typing import Any
from urllib.parse import urlparse

from mavr.observability.logging import get_logger
from mavr.schemas import entities as schema

log = get_logger(__name__)


# ---- enums & data ---------------------------------------------------------


class DecisionKind(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    QUARANTINE = "quarantine"


class ActionClass(str, Enum):
    READ = "read"
    WRITE = "write"
    ENUMERATION = "enumeration"
    ACTIVE_TEST = "active_test"
    EXFILTRATION = "exfiltration"
    DESTRUCTIVE = "destructive_mutation"
    CREDENTIAL_ATTACK = "credential_attack"
    DENIAL_OF_SERVICE = "denial_of_service"


# These action classes are always prohibited regardless of policy.
_FORBIDDEN_ACTION_CLASSES: set[str] = {
    ActionClass.DENIAL_OF_SERVICE.value,
    ActionClass.DESTRUCTIVE.value,
    ActionClass.CREDENTIAL_ATTACK.value,
    ActionClass.EXFILTRATION.value,
}


# Hard-coded network ranges that are NEVER reachable without an explicit
# human-approved override. Includes the cloud metadata IP and broadcast.
_BLOCKED_NETWORKS: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = (
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("169.254.0.0/16"),       # link-local + 169.254.169.254
    ipaddress.ip_network("10.0.0.0/8"),           # RFC1918
    ipaddress.ip_network("172.16.0.0/12"),        # RFC1918
    ipaddress.ip_network("192.168.0.0/16"),       # RFC1918
    ipaddress.ip_network("100.64.0.0/10"),        # CGNAT
    ipaddress.ip_network("224.0.0.0/4"),          # multicast
    ipaddress.ip_network("240.0.0.0/4"),          # reserved/broadcast
    ipaddress.ip_network("0.0.0.0/8"),            # unspecified
    ipaddress.ip_network("169.254.169.254/32"),   # explicit metadata IP
    ipaddress.ip_network("fc00::/7"),             # IPv6 ULA
    ipaddress.ip_network("fe80::/10"),            # IPv6 link-local
)

_SCHEMES: tuple[str, ...] = ("http", "https")

_HOST_PORT_RE = re.compile(r"^(?P<host>[^:]+|\[.+\])(?::(?P<port>\d+))?$")


# ---- decision object ------------------------------------------------------


@dataclass(frozen=True)
class PolicyDecision:
    kind: DecisionKind
    reason: str
    rule: str
    details: dict[str, Any] | None = None


@dataclass(frozen=True)
class ToolCall:
    url: str
    method: str = "GET"
    action_class: str = ActionClass.READ.value
    payload_summary: str = ""
    resolved_ips: tuple[str, ...] = ()


@dataclass(frozen=True)
class RateCounter:
    per_minute: int = 0


# ---- engine --------------------------------------------------------------


class ScopePolicyEngine:
    """Stateless engine: a campaign + scope policy object drives decisions."""

    def __init__(self, *, resolve_dns: bool = True) -> None:
        self._resolve_dns = resolve_dns

    # ---- main entry point ------------------------------------------------

    def evaluate(
        self,
        campaign: schema.Campaign,
        scope: schema.ScopePolicy,
        call: ToolCall,
        rate: RateCounter | None = None,
    ) -> PolicyDecision:
        # 1. Forbidden action classes
        if call.action_class in _FORBIDDEN_ACTION_CLASSES:
            return PolicyDecision(
                DecisionKind.DENY,
                f"action class {call.action_class!r} is always prohibited",
                "forbidden_action_class",
            )

        # 2. Parse + scheme
        try:
            parsed = urlparse(call.url)
        except ValueError as exc:
            return PolicyDecision(DecisionKind.DENY, f"invalid URL: {exc}", "invalid_url")

        if parsed.scheme.lower() not in _SCHEMES:
            return PolicyDecision(
                DecisionKind.DENY,
                f"scheme {parsed.scheme!r} not allowed (only http/https)",
                "bad_scheme",
            )

        # 3. Method allowlist
        method = call.method.upper()
        if method not in {m.upper() for m in scope.allowed_methods}:
            return PolicyDecision(
                DecisionKind.DENY,
                f"method {method!r} not in policy allowlist",
                "method_not_allowed",
                {"allowed": sorted(scope.allowed_methods)},
            )

        # 4. Action-class allowlist (campaign can be more restrictive than engine)
        if scope.action_allowlist and call.action_class not in scope.action_allowlist:
            return PolicyDecision(
                DecisionKind.DENY,
                f"action class {call.action_class!r} not in scope.action_allowlist",
                "action_not_allowed",
            )

        # 5. Active testing requires human approval
        if call.action_class == ActionClass.ACTIVE_TEST.value and not scope.human_approved:
            return PolicyDecision(
                DecisionKind.QUARANTINE,
                "active testing requires human_approved on the scope policy",
                "active_testing_unapproved",
            )

        # 6. Target allowlist
        host = (parsed.hostname or "").lower()
        if not host:
            return PolicyDecision(DecisionKind.DENY, "URL is missing a host", "no_host")
        if scope.allowed_targets and not self._target_matches(host, scope.allowed_targets):
            return PolicyDecision(
                DecisionKind.DENY,
                f"host {host!r} not in scope.allowed_targets",
                "host_not_in_scope",
            )

        # 7. SSRF / private network check
        unsafe_override = scope.explicit_unsafe_networking and scope.human_approved
        if not unsafe_override:
            blocked, ip, detail = self._check_ssrf(host, call.resolved_ips)
            if blocked:
                return PolicyDecision(
                    DecisionKind.DENY,
                    f"target {host!r} ({ip}) is in a denied network range",
                    "ssrf_denylist",
                    detail,
                )

        # 8. Rate limit
        if rate is not None and scope.rate_limit_per_minute and rate.per_minute > scope.rate_limit_per_minute:
            return PolicyDecision(
                DecisionKind.QUARANTINE,
                f"rate {rate.per_minute}/min exceeds limit {scope.rate_limit_per_minute}/min",
                "rate_limit_exceeded",
            )

        return PolicyDecision(DecisionKind.ALLOW, "ok", "pass")

    # ---- helpers ---------------------------------------------------------

    @staticmethod
    def _target_matches(host: str, allowed: list[str]) -> bool:
        for pattern in allowed:
            pat = pattern.strip().lower()
            if not pat:
                continue
            if pat.startswith("*."):
                suffix = pat[2:]
                if host.endswith("." + suffix) or host == suffix:
                    return True
                continue
            if host == pat:
                return True
            # simple glob with leading wildcard like "*example.com"
            if "*" in pat:
                regex = "^" + re.escape(pat).replace(r"\*", ".*") + "$"
                if re.match(regex, host):
                    return True
        return False

    @staticmethod
    def _ip_in_blocked(ip_str: str) -> tuple[bool, ipaddress._BaseAddress | None]:
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            return False, None
        for net in _BLOCKED_NETWORKS:
            if ip.version != net.version:
                continue
            if ip in net:
                return True, ip
        return False, ip

    def _check_ssrf(
        self, host: str, pre_resolved: tuple[str, ...]
    ) -> tuple[bool, str, dict[str, Any]]:
        # If the caller pre-resolved IPs (recommended), check those first.
        ips = list(pre_resolved) if pre_resolved else []
        if not ips and self._resolve_dns:
            try:
                infos = socket.getaddrinfo(host, None)
            except socket.gaierror:
                # Unknown host — let the request fail naturally; allow here.
                return False, "", {"note": "dns resolution failed", "host": host}
            ips = list({i[4][0] for i in infos})

        for ip_str in ips:
            # strip IPv6 zone if present
            ip_clean = ip_str.split("%", 1)[0]
            blocked, ip_obj = self._ip_in_blocked(ip_clean)
            if blocked:
                return True, ip_clean, {"host": host, "ip": ip_clean, "range": str(ip_obj)}
        return False, "", {"host": host, "ips": ips}

    @staticmethod
    def resolve_now(host: str) -> tuple[str, ...]:
        """Resolve ``host`` at request time and return the IP set.

        Used by callers to defend against DNS rebinding: resolve first,
        then pass the IPs into :class:`ToolCall`.
        """
        try:
            infos = socket.getaddrinfo(host, None)
        except socket.gaierror:
            return ()
        return tuple(sorted({i[4][0] for i in infos}))


# ---- convenience ---------------------------------------------------------


def evaluate_url(
    engine: ScopePolicyEngine,
    campaign: schema.Campaign,
    scope: schema.ScopePolicy,
    url: str,
    *,
    method: str = "GET",
    action_class: str = ActionClass.READ.value,
    payload_summary: str = "",
) -> PolicyDecision:
    host = (urlparse(url).hostname or "").lower()
    ips = ScopePolicyEngine.resolve_now(host) if host else ()
    call = ToolCall(
        url=url, method=method, action_class=action_class,
        payload_summary=payload_summary, resolved_ips=ips,
    )
    return engine.evaluate(campaign, scope, call)
