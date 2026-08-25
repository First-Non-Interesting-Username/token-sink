"""Policy-layer recognition hooks for the mock target (issue #95).

The fixture server's loopback URLs are private addresses, so the SSRF guard
and default-deny scope would normally block them. These helpers let an
operator (never an agent) register a running fixture as an *approved local
target*: scope entries + `private_network_authorized` scoped to exactly the
fixture base URL, while still emitting audit events so every fixture hit is
on the record.

This deliberately does NOT open a general private-network bypass — approval
is per-base-URL and revocable.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse

from policy.audit import AuditLog
from policy.scope import TargetSpec

EVENT_FIXTURE_APPROVED = "mock_target.approved"
EVENT_FIXTURE_REVOKED = "mock_target.revoked"


@dataclass
class FixtureApproval:
    """An operator-granted approval for one running fixture instance."""

    base_url: str
    campaign_uuid: str
    approved_by: str  # human identifier; agents must never set this


def _assert_loopback(base_url: str) -> None:
    host = urlparse(base_url).hostname or ""
    if host not in ("127.0.0.1", "localhost", "::1"):
        raise ValueError(f"fixture approvals are loopback-only, got host {host!r}")


def approve_fixture(
    audit_log: AuditLog, base_url: str, campaign_uuid: str, approved_by: str
) -> FixtureApproval:
    """Register an operator approval for a fixture base URL.

    Returns the approval object whose fields feed into ScopePolicy:
    add ``TargetSpec(f"{base_url}/", kind='url')`` to in_scope and treat
    requests to this exact origin with private_network_authorized=True.
    """
    _assert_loopback(base_url)
    if not approved_by or approved_by.startswith("agent:"):
        raise ValueError("fixture approval requires a human actor")
    approval = FixtureApproval(
        base_url=base_url, campaign_uuid=campaign_uuid, approved_by=approved_by
    )
    # Audit even though it's "just" a local fixture — §15 audit trail applies.
    audit_log.append(
        EVENT_FIXTURE_APPROVED,
        {"base_url": base_url, "campaign_uuid": campaign_uuid},
        actor=f"human:{approved_by}",
    )
    return approval


def revoke_fixture(audit_log: AuditLog, approval: FixtureApproval) -> None:
    """Revoke an approval; the audit record keeps history intact."""
    _assert_loopback(approval.base_url)
    audit_log.append(
        EVENT_FIXTURE_REVOKED,
        {"base_url": approval.base_url, "campaign_uuid": approval.campaign_uuid},
        actor="system",
    )


def in_scope_spec(approval: FixtureApproval) -> TargetSpec:
    """The TargetSpec to add to ScopePolicy.in_scope for this fixture."""
    return TargetSpec(approval.base_url.rstrip("/") + "/", kind="url")
