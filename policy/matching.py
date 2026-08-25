"""Scope matcher semantics (PLAN §5, issue #134): canonicalization + exact,
explainable matching rules for scope targets.

This module is the single source of truth for HOW a scope rule matches a
request target. It is a pure function set over (rule set, descriptor) so it
is trivially unit-testable and reusable by CLI pre-flight checks.

Key semantics (deliberate, tested):
- Hosts are CANONICALIZED before comparison: IDN/punycode → ASCII, case
  folding, trailing-dot stripping, default-port removal. This closes
  lookalike bypasses (`exämple.com`, `example.com.`, `example.com:443`).
- Subdomain inclusion is OPT-IN per rule: `include_subdomains=True` on a
  domain rule makes `api.example.com` match `example.com`; without the flag
  only exact host equality matches. Default is deny-by-narrowness.
- URL rules support path-prefix vs path-segment matching: `segment` mode
  never matches `/api-v2` for rule `/api` (prefix mode does) — segment is
  the safer default.
- Scheme allowlists are evaluated at match time so a rule can restrict to
  https even when the campaign broadly allows http.
- Explicit out-of-scope ALWAYS wins over in-scope when both match.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from urllib.parse import urlparse

DEFAULT_PORTS = {"http": 80, "https": 443}


# ---------------------------------------------------------------------------
# Canonicalization
# ---------------------------------------------------------------------------


def canonicalize_host(host: str | None) -> str:
    """Canonical form of a hostname/IP-literal for comparisons.

    - lower-case, strip one trailing root dot
    - IDN labels converted via IDNA (punycode); already-ASCII hosts are kept
      as-is so IP literals and punycode pass through unchanged
    """
    if not host:
        return ""
    h = host.strip().lower().rstrip(".")
    if not h:
        return ""
    try:
        h.encode("ascii")
        return h
    except UnicodeEncodeError:
        pass
    try:
        # IDNA 2003 via stdlib is adequate here: it maps fullwidth/fancy
        # unicode variants onto their ASCII forms, which is what we want
        # for security comparison (fail toward matching, then deny).
        return h.encode("idna").decode("ascii").lower()
    except UnicodeError:
        # Un-representable host: return something that cannot equal any
        # sane in-scope rule — fail closed.
        return "\x00" + h


def canonicalize_url(url: str) -> dict:
    """Canonical decomposition of a URL for rule matching."""
    try:
        parsed = urlparse(url)
    except ValueError:
        parsed = urlparse("")
    host = canonicalize_host(parsed.hostname)
    port = parsed.port
    scheme = (parsed.scheme or "").lower()
    if port is not None and DEFAULT_PORTS.get(scheme) == port:
        port = None  # default ports are stripped: :443 on https == bare https
    path = parsed.path or "/"
    return {
        "scheme": scheme,
        "host": host,
        "port": port,
        "path": path.rstrip("/") or "/",
        "userinfo": bool(parsed.username or parsed.password),
    }


# ---------------------------------------------------------------------------
# Rules and results
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ScopeRule:
    """One machine-checkable scope rule with an identity for explanations."""

    rule_id: str
    value: str
    kind: str = "auto"  # auto | domain | url | cidr | name
    include_subdomains: bool = False
    path_mode: str = "segment"  # prefix | segment (URL rules)
    allowed_schemes: tuple[str, ...] | None = None  # None = any allowed scheme
    out: bool = False  # True => explicit out-of-scope rule

    def __post_init__(self) -> None:
        if self.kind not in ("auto", "domain", "url", "cidr", "name"):
            raise ValueError(f"unknown rule kind: {self.kind!r}")
        if self.path_mode not in ("prefix", "segment"):
            raise ValueError(f"unknown path_mode: {self.path_mode!r}")


@dataclass(frozen=True)
class MatchResult:
    """Structured decision with provenance (issue #134 requirements)."""

    classification: str  # 'in' | 'out' | 'unlisted'
    rule_id: str  # '' when unlisted
    reason: str
    evaluated_field: str  # which request field drove the decision
    matched_value: str = ""


def _rule_kind(rule: ScopeRule) -> str:
    if rule.kind != "auto":
        return rule.kind
    v = rule.value
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


def _host_matches(rule_host: str, req_host: str, subdomains: bool) -> bool:
    if req_host == rule_host:
        return True
    # Subdomain inclusion is opt-in; also require a real label boundary so
    # `evilexample.com` can never match `example.com`.
    return subdomains and req_host.endswith("." + rule_host)


def _match_rule(rule: ScopeRule, canon: dict, raw_target: str) -> MatchResult | None:
    kind = _rule_kind(rule)

    if kind == "name":
        if raw_target.strip() == rule.value:
            return MatchResult(
                "in" if not rule.out else "out",
                rule.rule_id,
                f"exact name match on {rule.value!r}",
                "target",
                rule.value,
            )
        return None

    if kind == "cidr":
        try:
            ip = ipaddress.ip_address(canon["host"])
        except ValueError:
            return None
        if ip in ipaddress.ip_network(rule.value, strict=False):
            return MatchResult(
                "out" if rule.out else "in",
                rule.rule_id,
                f"IP {canon['host']} within CIDR {rule.value}",
                "target.host",
                rule.value,
            )
        return None

    if kind == "domain":
        rule_host = canonicalize_host(rule.value)
        if _host_matches(rule_host, canon["host"], rule.include_subdomains):
            # Scheme allowlist applies per-rule when configured.
            if rule.allowed_schemes and canon["scheme"] not in rule.allowed_schemes:
                return None
            why = "exact host" if canon["host"] == rule_host else "subdomain of"
            return MatchResult(
                "out" if rule.out else "in",
                rule.rule_id,
                f"{why} {rule.value!r}",
                "target.host",
                rule.value,
            )
        return None

    # url rule: host + path semantics + optional scheme restriction
    rc = canonicalize_url(rule.value)
    if not _host_matches(rc["host"], canon["host"], rule.include_subdomains):
        return None
    if rule.allowed_schemes and canon["scheme"] not in rule.allowed_schemes:
        return None
    rule_path = rc["path"]
    req_path = canon["path"]
    if rule.path_mode == "prefix":
        path_ok = req_path.startswith(rule_path) or req_path == "/"
    else:
        # segment mode: /api must not swallow /api-v2
        path_ok = req_path == rule_path or req_path.startswith(rule_path + "/") or rule_path == "/"
    if path_ok:
        return MatchResult(
            "out" if rule.out else "in",
            rule.rule_id,
            f"url rule {rule.value!r} ({rule.path_mode} path)",
            "target.url",
            rule.value,
        )
    return None


def classify(
    rules_in_scope: list[ScopeRule],
    rules_out_scope: list[ScopeRule],
    target: str,
) -> MatchResult:
    """Classify a request target against the rule sets.

    Out-of-scope always wins over in-scope when both match; unlisted is the
    default-deny outcome. Pure function of (rules, target).
    """
    looks_like_url = "://" in target or target.lower().startswith("//")
    canon = canonicalize_url(target if looks_like_url else f"https://{target}/")

    for rule in rules_out_scope:
        m = _match_rule(rule, canon, target)
        if m:
            return m  # explicit exclusion wins unconditionally
    for rule in rules_in_scope:
        m = _match_rule(rule, canon, target)
        if m:
            return m
    return MatchResult("unlisted", "", "no scope rule matched (default-deny)", "target")


@dataclass(frozen=True)
class ScopeRuleSet:
    """Bundle passed around by callers; keeps in/out lists consistent."""

    in_scope: list[ScopeRule] = field(default_factory=list)
    out_of_scope: list[ScopeRule] = field(default_factory=list)

    def classify(self, target: str) -> MatchResult:
        return classify(self.in_scope, self.out_of_scope, target)


# ---------------------------------------------------------------------------
# Adapters between the legacy TargetSpec model (#8) and rules (#134)
# ---------------------------------------------------------------------------


def spec_to_rule(
    spec,
    *,
    rule_id: str,
    out: bool = False,
    include_subdomains: bool = False,
    path_mode: str = "segment",
) -> ScopeRule:
    """Build a ScopeRule from a policy.scope.TargetSpec."""
    return ScopeRule(
        rule_id=rule_id,
        value=spec.value,
        kind=spec.kind,
        include_subdomains=include_subdomains,
        path_mode=path_mode,
        out=out,
    )
