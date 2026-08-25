"""Tests for the finding lifecycle state machine."""
from __future__ import annotations

import pytest

from mavr.findings import lifecycle
from mavr.schemas import entities as schema

ACTOR = "11111111-1111-4111-8111-111111111111"


@pytest.mark.asyncio
async def test_full_happy_path(migrated_db, campaign_id) -> None:
    async with migrated_db.acquire() as conn:
        f = await lifecycle.insert(
            conn, campaign_id=campaign_id, title="XSS in search", severity=schema.Severity.MEDIUM
        )
        assert f.state == schema.FindingState.INITIAL
        for new in [
            schema.FindingState.REVIEW_CYCLE_1,
            schema.FindingState.VALIDATED,
            schema.FindingState.IMPACT,
            schema.FindingState.POC_DRAFT,
            schema.FindingState.POC_REVIEW,
            schema.FindingState.POLISHED,
            schema.FindingState.FINAL_REVIEW,
            schema.FindingState.VULNERABILITY,
        ]:
            f = await lifecycle.transition(
                conn,
                finding_id=f.id,
                new_state=new,
                actor_id=ACTOR,
                reason="advancing",
            )
        assert f.state == schema.FindingState.VULNERABILITY
        history = await lifecycle.history(conn, f.id)
        # 1 creation + 8 transitions = 9 entries
        assert len(history) == 9
        # Append-only
        for entry in history:
            assert "created_at" in entry


@pytest.mark.asyncio
async def test_illegal_transition_raises(migrated_db, campaign_id) -> None:
    async with migrated_db.acquire() as conn:
        f = await lifecycle.insert(
            conn, campaign_id=campaign_id, title="t"
        )
        with pytest.raises(lifecycle.FindingStateError):
            await lifecycle.transition(
                conn,
                finding_id=f.id,
                new_state=schema.FindingState.VULNERABILITY,
                actor_id=ACTOR,
            )


@pytest.mark.asyncio
async def test_dispute_branch(migrated_db, campaign_id) -> None:
    async with migrated_db.acquire() as conn:
        f = await lifecycle.insert(conn, campaign_id=campaign_id, title="t")
        await lifecycle.transition(
            conn, finding_id=f.id, new_state=schema.FindingState.REVIEW_CYCLE_1, actor_id=ACTOR
        )
        await lifecycle.transition(
            conn, finding_id=f.id, new_state=schema.FindingState.DISPUTED, actor_id=ACTOR
        )
        # dispute loops back to review_cycle_1
        f = await lifecycle.transition(
            conn, finding_id=f.id, new_state=schema.FindingState.REVIEW_CYCLE_1, actor_id=ACTOR
        )
        assert f.state == schema.FindingState.REVIEW_CYCLE_1


@pytest.mark.asyncio
async def test_tombstone_path(migrated_db, campaign_id) -> None:
    async with migrated_db.acquire() as conn:
        f = await lifecycle.insert(conn, campaign_id=campaign_id, title="t")
        f = await lifecycle.transition(
            conn,
            finding_id=f.id,
            new_state=schema.FindingState.TOMBSTONED,
            actor_id=ACTOR,
            reason="false positive",
        )
        assert f.tombstoned
        with pytest.raises(lifecycle.FindingStateError):
            await lifecycle.transition(
                conn,
                finding_id=f.id,
                new_state=schema.FindingState.VULNERABILITY,
                actor_id=ACTOR,
            )


@pytest.mark.asyncio
async def test_version_bump_on_artifact_states(migrated_db, campaign_id) -> None:
    async with migrated_db.acquire() as conn:
        f = await lifecycle.insert(conn, campaign_id=campaign_id, title="t")
        assert f.current_version == 1
        f = await lifecycle.transition(
            conn, finding_id=f.id, new_state=schema.FindingState.REVIEW_CYCLE_1, actor_id=ACTOR
        )
        f = await lifecycle.transition(
            conn, finding_id=f.id, new_state=schema.FindingState.VALIDATED, actor_id=ACTOR
        )
        f = await lifecycle.transition(
            conn, finding_id=f.id, new_state=schema.FindingState.IMPACT, actor_id=ACTOR
        )
        assert f.current_version == 2


@pytest.mark.asyncio
async def test_artifact_path_for_known_states(migrated_db, campaign_id) -> None:
    async with migrated_db.acquire() as conn:
        f = await lifecycle.insert(conn, campaign_id=campaign_id, title="t")
        path = lifecycle.artifact_path_for(f, schema.FindingState.INITIAL)
        assert path.endswith("initial_findings.md")
        # Unknown state -> error
        with pytest.raises(lifecycle.FindingStateError):
            lifecycle.artifact_path_for(f, schema.FindingState.VULNERABILITY)


@pytest.mark.asyncio
async def test_lease_round_trip(migrated_db, campaign_id) -> None:
    async with migrated_db.acquire() as conn:
        f = await lifecycle.insert(conn, campaign_id=campaign_id, title="t")
        lease = await lifecycle.lease(conn, finding_id=f.id, owner=ACTOR)
        assert lease is not None
        # second agent blocked
        other = "22222222-2222-4222-8222-222222222222"
        blocked = await lifecycle.lease(conn, finding_id=f.id, owner=other)
        assert blocked is None
        # release
        ok = await lifecycle.release_lease(conn, finding_id=f.id, owner=ACTOR)
        assert ok
        again = await lifecycle.lease(conn, finding_id=f.id, owner=other)
        assert again is not None


@pytest.mark.asyncio
async def test_lease_does_not_clobber_concurrent_transition_metadata(
    migrated_db, campaign_id
) -> None:
    """Regression: leases must be independent of finding_transitions.

    A concurrent transition() between lease() and release_lease() must
    not modify or be modified by the lease row.
    """
    async with migrated_db.acquire() as conn:
        f = await lifecycle.insert(conn, campaign_id=campaign_id, title="t")
        lease = await lifecycle.lease(conn, finding_id=f.id, owner=ACTOR)
        assert lease is not None
        f = await lifecycle.transition(
            conn,
            finding_id=f.id,
            new_state=schema.FindingState.REVIEW_CYCLE_1,
            actor_id=ACTOR,
            metadata={"note": "in-flight review"},
        )
        # lease is still live; the most-recent transition metadata must
        # not have absorbed a lease key.
        history = await lifecycle.history(conn, f.id)
        last = history[-1]
        assert "lease" not in last["metadata"]
        assert last["metadata"]["note"] == "in-flight review"
        # and release_lease still works
        ok = await lifecycle.release_lease(conn, finding_id=f.id, owner=ACTOR)
        assert ok
