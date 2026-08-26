"""Tests for conflicting-edit resolution (PLAN §18, issue #132)."""

import pytest

from findings.concurrency import (
    ConcurrencyControl,
    ConflictError,
    NotLeaseHolderError,
    StaleLeaseError,
)
from findings.lifecycle import FindingLifecycle, RecordStore

AGENT = "11111111-1111-1111-1111-111111111111"
REVIEWER = "22222222-2222-2222-2222-222222222222"
OTHER = "55555555-5555-5555-5555-555555555555"
CAMPAIGN = "44444444-4444-4444-4444-444444444444"


@pytest.fixture()
def env():
    lc = FindingLifecycle(RecordStore())
    res = lc.submit_finding(CAMPAIGN, AGENT, {"title": "XSS in profile", "category": "xss"})
    lc.claim_for_review(res.finding.finding_uuid, REVIEWER, "2099-01-01T00:00:00+00:00")
    cc = ConcurrencyControl(lc.store)
    return lc, cc, res.finding.finding_uuid


def test_happy_path_write_bumps_version_and_logs(env):
    lc, cc, fuid = env
    v0 = cc.current_version(fuid)
    v1 = cc.update(
        fuid,
        REVIEWER,
        v0,
        lambda f: setattr(f, "observation", "reflected XSS confirmed"),
        reason="add_observation",
    )
    assert v1 == v0 + 1
    hist = lc.store.history(fuid)
    assert hist[-1].reason == "guarded_write:add_observation"


def test_version_conflict_rejected_and_audited(env):
    lc, cc, fuid = env
    stale = cc.current_version(fuid)
    # Another legitimate write lands first.
    cc.update(fuid, REVIEWER, stale, lambda f: setattr(f, "confidence", 0.8))
    with pytest.raises(ConflictError) as exc:
        cc.update(
            fuid,
            REVIEWER,
            stale,
            lambda f: setattr(f, "observation", "based on a stale read"),
        )
    assert exc.value.expected_version == stale
    assert exc.value.actual_version == stale + 1
    # Audit trail records the rejection...
    rejections = cc.rejected_writes(fuid)
    assert len(rejections) == 1
    assert rejections[0].expected_version == stale
    # ...but a rejected write must NOT advance the version — otherwise one
    # conflict instantly stales every other in-flight writer (cascade).
    assert cc.current_version(fuid) == stale + 1
    # The losing edit never landed.
    assert lc.store.load(fuid).observation != "based on a stale read"


def test_non_holder_cannot_write_in_leased_state(env):
    _lc, cc, fuid = env
    v = cc.current_version(fuid)
    with pytest.raises(NotLeaseHolderError):
        cc.update(fuid, OTHER, v, lambda f: setattr(f, "title", "hijack"))
    # Nothing changed — no new version, no hijacked title.
    assert cc.current_version(fuid) == v
    assert cc.store.load(fuid).title != "hijack"


def test_expired_lease_is_stale(env):
    lc, _cc, fuid = env

    finding = lc.store.load(fuid)
    finding.lease.expires_at = "2000-01-01T00:00:00+00:00"
    cc = ConcurrencyControl(lc.store)
    with pytest.raises(StaleLeaseError):
        cc.update(fuid, REVIEWER, 99, lambda f: None)


def test_lease_not_required_outside_leased_states():
    lc = FindingLifecycle(RecordStore())
    res = lc.submit_finding(CAMPAIGN, AGENT, {"title": "t", "category": "c"})
    fuid = res.finding.finding_uuid
    # Advance out of review into post-first-review states without lease:
    # record_first_review requires the lease, so go through it properly.
    lc.claim_for_review(fuid, REVIEWER, "2099-01-01T00:00:00+00:00")
    lc.record_first_review(fuid, REVIEWER, "confirmed")
    for _ in range(6):
        lc.advance(fuid, REVIEWER)  # transitions clear the lease
    cc = ConcurrencyControl(lc.store)
    v = cc.current_version(fuid)
    new_v = cc.update(fuid, OTHER, v, lambda f: setattr(f, "suspected_impact", "low"))
    assert new_v == v + 1


def test_unknown_finding_rejected():
    from findings.lifecycle import LifecycleError

    cc = ConcurrencyControl(RecordStore())
    with pytest.raises(LifecycleError):
        cc.update("00000000-0000-0000-0000-000000000000", OTHER, 0, lambda f: None)


def test_resolve_conflict_last_write_wins(env):
    lc, cc, fuid = env
    v = cc.current_version(fuid)
    cc.update(fuid, REVIEWER, v, lambda f: setattr(f, "title", "v1"))
    current = cc.current_version(fuid)
    new_v = cc.resolve_conflict(
        fuid,
        REVIEWER,
        {"title": "adjudicated title"},
        strategy="last_write_wins",
        expected_version=current,
    )
    assert lc.store.load(fuid).title == "adjudicated title"
    assert any(t.reason == "conflict_resolved:last_write_wins" for t in lc.store.history(fuid))
    assert new_v > v


def test_resolve_conflict_discard_keeps_current_but_logs(env):
    lc, cc, fuid = env
    v = cc.current_version(fuid)
    before = lc.store.load(fuid).title
    current = cc.current_version(fuid)
    new_v = cc.resolve_conflict(
        fuid,
        REVIEWER,
        {"title": "losing edit"},
        strategy="discard_incoming",
        expected_version=current,
    )
    assert lc.store.load(fuid).title == before
    t = lc.store.history(fuid)[-1]
    assert t.reason == "conflict_resolved:discard_incoming"
    assert t.payload["winner"] == {"title": "losing edit"}
    assert new_v > v


def test_resolve_conflict_is_guarded_by_version_check(env):
    """Adjudication must not be a side door around optimistic concurrency."""
    lc, cc, fuid = env
    stale = cc.current_version(fuid)
    cc.update(fuid, REVIEWER, stale, lambda f: setattr(f, "confidence", 0.9))
    with pytest.raises(ConflictError):
        cc.resolve_conflict(
            fuid,
            REVIEWER,
            {"title": "sneaky overwrite"},
            strategy="last_write_wins",
            expected_version=stale,
        )
    assert lc.store.load(fuid).title != "sneaky overwrite"
    # The failed adjudication is audited like any rejected write.
    assert len(cc.rejected_writes(fuid)) == 1


def test_resolve_conflict_requires_lease_in_leased_state(env):
    _lc, cc, fuid = env
    with pytest.raises(NotLeaseHolderError):
        cc.resolve_conflict(
            fuid,
            OTHER,
            {"title": "hijack"},
            strategy="last_write_wins",
        )
    assert cc.store.load(fuid).title != "hijack"


def test_prior_versions_are_not_mutated_by_later_writes(env):
    """Stored versions are frozen snapshots; writes create a new head."""
    lc, cc, fuid = env
    v = cc.current_version(fuid)
    before_title = lc.store.load(fuid).title
    snapshot = copy_of(lc.store.load(fuid))
    cc.update(fuid, REVIEWER, v, lambda f: setattr(f, "title", "changed"))
    stored = lc.store._versions[fuid][0]  # first stored version
    assert vars(stored) == vars(snapshot), "stored version was mutated in place"
    assert before_title == snapshot.title


def copy_of(f):
    import copy as _copy

    return _copy.deepcopy(f)


def test_unknown_resolution_strategy(env):
    from findings.lifecycle import LifecycleError

    _lc, cc, fuid = env
    with pytest.raises(LifecycleError):
        cc.resolve_conflict(fuid, REVIEWER, {}, strategy="overwrite_both")


def test_conflict_then_retry_with_current_version_succeeds(env):
    """After a rejection, a rebased write at the CURRENT version lands fine."""
    lc, cc, fuid = env
    stale = cc.current_version(fuid)
    cc.update(fuid, REVIEWER, stale, lambda f: setattr(f, "confidence", 0.7))
    with pytest.raises(ConflictError):
        cc.update(fuid, REVIEWER, stale, lambda f: None)
    current = cc.current_version(fuid)
    v = cc.update(fuid, REVIEWER, current, lambda f: setattr(f, "confidence", 0.75))
    assert v == current + 1
