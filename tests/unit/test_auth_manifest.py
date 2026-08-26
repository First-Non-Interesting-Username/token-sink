"""Unit tests for the campaign authorization manifest (issue #160).

Table-driven over: tamper detection, expiry/revocation gating, import/export
round-trips, loud manifest-vs-config mismatch validation, and refusal to
allow active testing without a valid manifest.
"""

from __future__ import annotations

import pytest

from policy.auth_manifest import (
    AuthorizationManifest,
    ManifestError,
    ManifestExpiredError,
    ManifestMismatchError,
    ManifestRevokedError,
    SignOff,
    TamperedManifestError,
    active_testing_allowed,
    validate_against_scope,
    verify_exported,
)
from policy.scope import RateLimit, ScopePolicy, TargetSpec

T0 = "2026-08-01T00:00:00+00:00"
T1 = "2026-09-01T00:00:00+00:00"  # one month after T0


def _sign_off() -> SignOff:
    return SignOff(approver="alice", approved_at=T0, reference="contract-7")


def _manifest(**overrides) -> AuthorizationManifest:
    kwargs = dict(
        program_id="Hack Club Security",
        issued_at=T0,
        expires_at=T1,
        sign_off=_sign_off(),
        in_scope=["*.example.com"],
        out_of_scope=["admin.example.com"],
        allowed_actions=["active_testing", "passive_recon"],
        prohibited_actions=["dos", "social_engineering"],
        rate_ceilings={"default": {"max_requests": 10, "per_seconds": 1}},
    )
    kwargs.update(overrides)
    return AuthorizationManifest(**kwargs)


def _scope(**overrides) -> ScopePolicy:
    kwargs = dict(
        campaign_uuid="c-1",
        program_name="Hack Club Security",
        in_scope=[TargetSpec("*.example.com")],
        out_of_scope=[TargetSpec("admin.example.com")],
        prohibited_actions={"dos", "social_engineering"},
        allowed_actions_override=None,
    )
    kwargs.update(overrides)
    kwargs.pop("allowed_actions_override", None)
    return ScopePolicy(**kwargs)


# -- structure ----------------------------------------------------------------


@pytest.mark.parametrize(
    "overrides",
    [
        {"program_id": ""},
        {"expires_at": T0, "issued_at": T0},  # expiry not after issue
    ],
)
def test_invalid_manifests_rejected(overrides: dict) -> None:
    with pytest.raises(ManifestError):
        _manifest(**overrides)


def test_missing_signoff_rejected() -> None:
    with pytest.raises(ManifestError):
        _manifest(sign_off=SignOff(approver="", approved_at=T0))


# -- integrity / tamper detection ----------------------------------------------


def test_export_round_trip_preserves_manifest() -> None:
    m = _manifest()
    restored = verify_exported(m.export(), now=lambda: T0)
    assert restored.to_dict() == m.to_dict()


def test_post_hoc_scope_edit_is_detected() -> None:
    bundle = _manifest().export()
    bundle["in_scope"] = ["*"]  # widen scope behind everyone's back
    with pytest.raises(TamperedManifestError):
        verify_exported(bundle, now=lambda: T0)


def test_bundle_without_hash_rejected() -> None:
    d = _manifest().to_dict()
    with pytest.raises(ManifestError):
        verify_exported(d, now=lambda: T0)


# -- expiry / revocation gating -------------------------------------------------


def _clock(ts: str):
    return lambda: ts


def test_expired_manifest_blocks_active_testing_but_reports_clearly() -> None:
    m = _manifest()
    assert active_testing_allowed(m, now=_clock("2026-08-15T00:00:00+00:00")) is True
    assert active_testing_allowed(m, now=_clock("2026-09-15T00:00:00+00:00")) is False
    with pytest.raises(ManifestExpiredError) as exc:
        m.check_validity(now=_clock("2026-09-15T00:00:00+00:00"))
    assert "renew" in str(exc.value).lower()


def test_revoked_manifest_never_allows_active_testing() -> None:
    m = _manifest(revoked_at="2026-08-05T00:00:00+00:00")
    for ts in (T0, "2026-08-10T00:00:00+00:00"):
        assert active_testing_allowed(m, now=_clock(ts)) is False
    with pytest.raises(ManifestRevokedError):
        m.check_validity(now=_clock(T0))


def test_boundary_expiry_is_exclusive() -> None:
    m = _manifest()
    with pytest.raises(ManifestExpiredError):
        m.check_validity(now=_clock(T1))


# -- loud mismatch validation -----------------------------------------------------


def test_matching_scope_passes() -> None:
    validate_against_scope(_manifest(), _scope())


@pytest.mark.parametrize(
    ("m_over", "s_over"),
    [
        ({"program_id": "Other Program"}, {}),
        ({}, {"program_name": "Something Else"}),
        ({"in_scope": ["*.other.com"]}, {}),
        ({}, {"in_scope": [TargetSpec("*.example.com"), TargetSpec("extra.com")]}),
        ({"out_of_scope": []}, {}),
        ({"prohibited_actions": ["dos"]}, {}),
        ({"allowed_actions": ["passive_recon"]}, {"active_testing_enabled": True}),
    ],
)
def test_any_mismatch_fails_loudly(m_over: dict, s_over: dict) -> None:
    with pytest.raises(ManifestMismatchError):
        validate_against_scope(_manifest(**m_over), _scope(**s_over))


def test_active_testing_blocked_without_manifest_grant_message_is_actionable() -> None:
    m = _manifest(allowed_actions=["passive_recon"])
    with pytest.raises(ManifestMismatchError) as exc:
        validate_against_scope(m, _scope(active_testing_enabled=True))
    assert "active testing" in str(exc.value).lower()


def test_rate_ceilings_round_trip_through_export() -> None:
    m = _manifest()
    restored = verify_exported(m.export(), now=lambda: T0)
    assert restored.rate_ceilings["default"] == {"max_requests": 10, "per_seconds": 1}


# -- integration shape: scope objects remain usable alongside manifests -----------


def test_manifest_targets_align_with_targetspec_values() -> None:
    scope = _scope(rate_limits={"default": RateLimit(max_requests=5, per_seconds=1)})
    m = _manifest()
    # No exception: manifest strings match TargetSpec values used by config.
    validate_against_scope(m, scope)
