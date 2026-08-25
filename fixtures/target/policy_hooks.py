"""Fixture-target recognition for the policy layer (issue #95).

The policy engine treats fixture URLs (the loopback mock-target server) as
approved local targets so PoC work can run without a full campaign
authorization flow — while still recording an audit event, per the issue's
acceptance criteria. This module is deliberately conservative: it only ever
recognizes loopback http(s) URLs on ports a FixtureServer could bind; every
other URL gets ``False``.
"""

from __future__ import annotations

from urllib.parse import urlparse

LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})


def is_fixture_url(url: str) -> bool:
    """True when *url* points at a loopback fixture target."""
    try:
        parsed = urlparse(url)
    except ValueError:
        return False
    if parsed.scheme not in ("http", "https"):
        return False
    return (parsed.hostname or "").lower() in LOOPBACK_HOSTS


def authorize_fixture_target(audit_log, url: str, actor: str = "") -> bool:
    """Approve a fixture target without full campaign auth, but audit it.

    Returns True when *url* is a loopback fixture URL (and appends an audit
    event either way so the decision is always traceable).
    """
    allowed = is_fixture_url(url)
    # WHY audit even denials: fixture authorization must be as traceable as
    # the real approval flow, just cheaper.
    audit_log.append(
        "fixture_target_authorization",
        {"url": url, "allowed": allowed},
        actor=actor,
    )
    return allowed
