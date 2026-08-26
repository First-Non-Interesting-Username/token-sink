"""Tests for finding quarantine semantics (#327, PLAN §2.5/§10.5)."""
from __future__ import annotations

import pytest

from mavr.findings import lifecycle, quarantine
from mavr.findings.quarantine import QuarantineError
from mavr.schemas import entities as schema


async def _finding(conn, campaign_id: str) -> schema.Finding:
    return await lifecycle.insert(
        conn, campaign_id=campaign_id, title="q-test", severity=schema.Severity.LOW
    )


@pytest.mark.asyncio
async def test_manual_quarantine_requires_reason(migrated_db, campaign_id) -> None:
    async with migrated_db.acquire() as conn:
        f = await _finding(conn, campaign_id)
        with pytest.raises(QuarantineError):
            await quarantine.enter_manual(
                conn, finding_id=f.id, actor_id=None, reason="  "
            )


@pytest.mark.asyncio
async def test_manual_quarantine_and_restore_roundtrip(migrated_db, campaign_id) -> None:
    async with migrated_db.acquire() as conn:
        f = await _finding(conn, campaign_id)
        q = await quarantine.enter_manual(
            conn,
            finding_id=f.id,
            actor_id="11111111-1111-4111-8111-111111111111",
            reason="operator hold",
            approval_ref="appr-1",
        )
        assert q.state == schema.FindingState.QUARANTINED
        # Preservation: version history + transitions intact.
        await quarantine.assert_preserved(
            conn, finding_id=f.id, expected_versions=0, expected_reviews=0
        )
        r = await quarantine.restore(conn, finding_id=f.id)
        assert r.state == schema.FindingState.INITIAL


@pytest.mark.asyncio
async def test_policy_fail_entry(migrated_db, campaign_id) -> None:
    async with migrated_db.acquire() as conn:
        f = await _finding(conn, campaign_id)
        q = await quarantine.enter_policy_fail(
            conn, finding_id=f.id, gate="poc_safety", detail="unsafe payload"
        )
        assert q.state == schema.FindingState.QUARANTINED
        with pytest.raises(QuarantineError):
            await quarantine.enter_policy_fail(
                conn, finding_id=f.id, gate="", detail=""
            )


@pytest.mark.asyncio
async def test_double_quarantine_rejected(migrated_db, campaign_id) -> None:
    async with migrated_db.acquire() as conn:
        f = await _finding(conn, campaign_id)
        await quarantine.enter_manual(
            conn, finding_id=f.id, actor_id=None, reason="hold"
        )
        with pytest.raises(QuarantineError):
            await quarantine.enter_manual(
                conn, finding_id=f.id, actor_id=None, reason="again"
            )


@pytest.mark.asyncio
async def test_restore_requires_quarantined_state(migrated_db, campaign_id) -> None:
    async with migrated_db.acquire() as conn:
        f = await _finding(conn, campaign_id)
        with pytest.raises(QuarantineError):
            await quarantine.restore(conn, finding_id=f.id)


@pytest.mark.asyncio
async def test_bounded_reentry_loop_flagged(migrated_db, campaign_id) -> None:
    async with migrated_db.acquire() as conn:
        f = await _finding(conn, campaign_id)
        for cycle in range(quarantine.MAX_QUARANTINE_CYCLES):
            await quarantine.enter_manual(
                conn, finding_id=f.id, actor_id=None, reason=f"cycle {cycle}"
            )
            await quarantine.restore(conn, finding_id=f.id)
        # Third entry is refused — unbounded loop cannot spin silently.
        with pytest.raises(QuarantineError, match="limit"):
            await quarantine.enter_manual(
                conn, finding_id=f.id, actor_id=None, reason="third"
            )


@pytest.mark.asyncio
async def test_restore_target_must_be_restorable(migrated_db, campaign_id) -> None:
    async with migrated_db.acquire() as conn:
        f = await _finding(conn, campaign_id)
        await quarantine.enter_manual(
            conn, finding_id=f.id, actor_id=None, reason="hold"
        )
        with pytest.raises(QuarantineError, match="restorable"):
            await quarantine.restore(
                conn, finding_id=f.id, to_state=schema.FindingState.VULNERABILITY
            )
        # Tombstone escalation stays on the dual-confirmation path; the
        # lifecycle allows quarantined → tombstoned directly.
        t = await lifecycle.transition(
            conn,
            finding_id=f.id,
            new_state=schema.FindingState.TOMBSTONED,
            actor_id=None,
            reason="escalated",
        )
        assert t.state == schema.FindingState.TOMBSTONED


@pytest.mark.asyncio
async def test_export_excludes_quarantined_by_default(migrated_db, campaign_id) -> None:
    async with migrated_db.acquire() as conn:
        f = await _finding(conn, campaign_id)
        g = await lifecycle.insert(conn, campaign_id=campaign_id, title="active")
        await quarantine.enter_manual(
            conn, finding_id=f.id, actor_id=None, reason="hold"
        )
        default = await quarantine.exportable_findings(conn, campaign_id=campaign_id)
        assert [x.id for x in default] == [g.id]
        explicit = await quarantine.exportable_findings(
            conn, campaign_id=campaign_id, include_quarantined=True
        )
        assert {x.id for x in explicit} == {f.id, g.id}
