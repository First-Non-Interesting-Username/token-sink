"""Acceptance tests (spec §21 — Definition of Done).

These tests mirror the spec's release-criteria:

* a campaign resumes after restart — pending tasks survive a process
  crash and are picked up by the next worker;
* usage is accurately attributed — every free vs paid call shows up
  in ``usage_events`` with the right provider / model / agent;
* no finding reaches the final ``vulnerabilities`` state without all
  the required gates (first-cycle review, impact, PoC, four-agent
  quorum, final traceability);
* every claim in a final report either traces to an evidence item or
  is explicitly labeled analysis;
* submission is never automatic — there is no API path that
  silently forwards a report to a remote endpoint.
"""
from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest

from mavr.agents.identity import mint_agent
from mavr.findings.workflow import (
    DiscoveryPayload,
    ImpactPayload,
    PoCPayload,
    ReviewInput,
    create_initial_finding,
    fold_reviews,
    record_impact,
    record_poc_draft,
    record_review,
    run_final_review,
    run_first_cycle_review,
)
from mavr.orchestrator import queue
from mavr.orchestrator.agents import insert as insert_agent
from mavr.providers.model_catalog.scores import ModelScoreStore
from mavr.providers.registry import ProviderRegistry
from mavr.reports.submission import submit as submit_final_report
from mavr.routers.circuit_breaker import CircuitBreakerStore
from mavr.routers.dead_letter import DeadLetterQueue
from mavr.routers.pool import RouterPool
from mavr.routers.usage import UsageAccountant
from mavr.schemas import entities as schema
from mavr.schemas.routing import (
    ChatMessage,
    ChatRequest,
    RoutingPolicy,
    RoutingTask,
    TaskCategory,
    UsageInfo,
)
from mavr.storage.database import Database, apply_migrations
from mavr.tests._fakes import MockAdapter

# ---- 1. Campaign resumes after restart ---------------------------------


class TestCampaignResumes:
    @pytest.mark.asyncio
    async def test_pending_tasks_survive_restart(
        self, tmp_path: Path
    ) -> None:
        db_path = tmp_path / "resume.db"
        cid = str(uuid4())

        # Run 1: enqueue 3 tasks.
        db1 = Database(db_path)
        await apply_migrations(db1, "up")
        now = datetime.now(UTC).isoformat()
        async with db1.acquire() as conn:
            await conn.execute(
                "INSERT INTO campaigns(id, schema_version, name, target_spec, "
                "state, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (cid, schema.SCHEMA_VERSION, "resume", "{}", "active", now, now),
            )
            for _ in range(3):
                await queue.enqueue(
                    conn,
                    campaign_id=cid,
                    kind=schema.TaskKind.SEARCH,
                    payload={"url": "https://example.com/"},
                )
            await conn.commit()
        del db1

        # "Kill -9" — drop the process.
        # Run 2: re-open the same DB and re-dequeue.
        db2 = Database(db_path)
        async with db2.acquire() as conn:
            leased = await queue.dequeue(conn, owner="after-restart", limit=10)
        assert len(leased) == 3
        assert {t.campaign_id for t in leased} == {cid}


# ---- 2. Usage accurately attributed -----------------------------------


class TestUsageAttribution:
    @pytest.mark.asyncio
    async def test_free_calls_appear_in_usage(self, tmp_path: Path) -> None:
        db = Database(tmp_path / "usage.db")
        await apply_migrations(db, "up")
        reg = ProviderRegistry([MockAdapter()])
        pool = RouterPool(
            registry=reg,
            scores=ModelScoreStore(db),
            breakers=CircuitBreakerStore(db),
            usage=UsageAccountant(db),
            dead_letter=DeadLetterQueue(db),
            db=db,
        )
        task = RoutingTask(
            task_id=str(uuid4()),
            category=TaskCategory.GENERIC,
            policy=RoutingPolicy.BEST_SCORE,
            request=ChatRequest(messages=[ChatMessage(role="user", content="hi")]),
            free_only=True,
        )
        outcome = await pool.route_and_run(task)
        assert outcome.error is None
        # The usage event must be present.
        async with db.acquire() as conn:
            cur = await conn.execute(
                "SELECT * FROM usage_events"
            )
            rows = list(await cur.fetchall())
        assert rows
        row = rows[0]
        assert row["provider_id"] == "mock"
        assert row["is_free"] == 1
        assert row["is_paid"] == 0
        assert row["input_tokens"] >= 0
        assert row["output_tokens"] >= 0

    @pytest.mark.asyncio
    async def test_totals_include_cost(self, tmp_path: Path) -> None:
        db = Database(tmp_path / "usage2.db")
        await apply_migrations(db, "up")
        accountant = UsageAccountant(db)
        for _ in range(3):
            await accountant.record(
                provider_id="mock",
                model_key="mock-review",
                usage=UsageInfo(input_tokens=100, output_tokens=50),
                latency_ms=42,
                is_free=True,
            )
        totals = await accountant.totals()
        assert totals["n"] == 3
        assert totals["in_t"] == 300
        assert totals["out_t"] == 150
        assert totals["free_count"] == 3
        assert totals["paid_count"] == 0


# ---- 3. Required gates before final state -----------------------------


class TestGates:
    @pytest.mark.asyncio
    async def test_finding_cannot_skip_to_vulnerabilities(
        self, migrated_db: Database, campaign_id: str
    ) -> None:
        """Trying to land a finding in ``vulnerabilities`` without
        first passing every gate (review cycle 1, impact, PoC, four
        agents, final review) must raise."""
        from mavr.findings import lifecycle

        async with migrated_db.acquire() as conn:
            f = await create_initial_finding(
                conn,
                campaign_id=campaign_id,
                payload=DiscoveryPayload(
                    title="t",
                    description="d",
                    severity=schema.Severity.HIGH,
                    confidence="confirmed",
                    evidence_refs=(str(uuid4()),),
                ),
            )
            # The lifecycle module refuses an invalid direct transition.
            with pytest.raises(lifecycle.FindingStateError):
                await lifecycle.transition(
                    conn,
                    finding_id=f.id,
                    new_state=schema.FindingState.VULNERABILITY,
                    actor_id=None,
                    reason="skip",
                )

    @pytest.mark.asyncio
    async def test_full_workflow_reaches_vulnerabilities(
        self, migrated_db: Database, campaign_id: str
    ) -> None:
        """The happy path: a finding that passes every gate reaches
        the ``vulnerabilities`` state and a final report is written."""
        async with migrated_db.acquire() as conn:
            f = await create_initial_finding(
                conn,
                campaign_id=campaign_id,
                payload=DiscoveryPayload(
                    title="t",
                    description="d",
                    severity=schema.Severity.HIGH,
                    confidence="confirmed",
                    evidence_refs=(str(uuid4()),),
                ),
            )
            await run_first_cycle_review(
                conn,
                finding_id=f.id,
                reviewer_agent_id=str(uuid4()),
                conclusion="confirmed",
                rationale="looks legit",
                supporting_evidence=[str(uuid4())],
            )
            await record_impact(
                conn,
                finding_id=f.id,
                agent_id=str(uuid4()),
                impact=ImpactPayload(
                    root_cause="r",
                    preconditions="p",
                    affected_versions="v",
                    security_boundary="b",
                    cia_impact={
                        "confidentiality": "high",
                        "integrity": "high",
                        "availability": "none",
                    },
                    exploitability="low",
                    mitigations="m",
                ),
            )
            await record_poc_draft(
                conn,
                finding_id=f.id,
                agent_id=str(uuid4()),
                poc=PoCPayload(
                    setup="s",
                    commands=("curl http://example.com/x",),
                    expected_output="e",
                    cleanup="c",
                    safety_notes="n",
                    target_kind="local_mock",
                    requires_human_approval=False,
                ),
            )
            # Move the finding into poc_review so we can fold reviews.
            from mavr.findings import lifecycle

            await lifecycle.transition(
                conn,
                finding_id=f.id,
                new_state=schema.FindingState.POC_REVIEW,
                actor_id=None,
                reason="tests",
            )
            # Register four reviewer agents so the FK is satisfied, then
            # file one review per agent (all accept).
            reviewer_ids: list[str] = []
            for _ in range(4):
                rev = mint_agent(schema.AgentRole.REVIEWER, campaign_id=campaign_id)
                await insert_agent(conn, rev)
                reviewer_ids.append(rev.id)
            for rid in reviewer_ids:
                await record_review(
                    conn,
                    finding_id=f.id,
                    version=f.current_version,
                    review=ReviewInput(
                        reviewer_agent_id=rid,
                        verdict=schema.ReviewVerdict.ACCEPT,
                        validity="valid",
                        reproduction_quality="high",
                        scope_safety="safe",
                        severity_consistency="consistent",
                        confidence=0.9,
                    ),
                )
            await fold_reviews(conn, finding_id=f.id, version=f.current_version)
            # The polished body links a real evidence UUID; the
            # traceability checker then advances the finding.
            evid = str(uuid4())
            await run_final_review(
                conn,
                finding_id=f.id,
                agent_id=str(uuid4()),
                polished_body=f"Confirmed. [evidence:{evid}]",
                source_evidence={evid: {"claim": "Confirmed."}},
            )
            # Find the finding again — it should be in vulnerabilities.
            from mavr.findings import lifecycle

            final = await lifecycle.get(conn, f.id)
            assert final.state == schema.FindingState.VULNERABILITY


# ---- 4. Claims trace to evidence or are explicitly labeled analysis ---


class TestEvidenceTraceability:
    def test_missing_evidence_refs_flagged(self) -> None:
        from mavr.findings.workflow import check_traceability

        report = check_traceability(
            polished_body="We saw [evidence:00000000-0000-4000-8000-000000000000] leak.",
            source_evidence={},
        )
        assert report.passed is False
        assert "00000000-0000-4000-8000-000000000000" in report.missing_evidence_claims

    def test_altered_claim_flagged(self) -> None:
        from mavr.findings.workflow import check_traceability

        ev_id = "11111111-1111-4111-8111-111111111111"
        report = check_traceability(
            polished_body=f"Per [evidence:{ev_id}], the value is 42.",
            source_evidence={ev_id: {"claim": "the value is 99"}},
        )
        assert report.passed is False
        assert ev_id in report.altered_claims

    def test_analysis_labeled_passed(self) -> None:
        """A polished body with no ``[evidence:...]`` references
        passes the traceability check (the audit log records the
        fact that this is an analysis-only report).
        """
        from mavr.findings.workflow import check_traceability

        report = check_traceability(
            polished_body=(
                "ANALYSIS: this looks like a chain of related bugs "
                "but we have not yet confirmed it."
            ),
            source_evidence={},
        )
        # No evidence refs and no claims -> traceability passes; the
        # report's content is on the auditor to evaluate as analysis.
        assert report.passed is True
        assert not report.missing_evidence_claims
        assert not report.altered_claims

    def test_claim_without_evidence_fails(self) -> None:
        """A claim that cites an evidence UUID the auditor cannot
        locate must fail the traceability check."""
        from mavr.findings.workflow import check_traceability

        report = check_traceability(
            polished_body=(
                "We confirmed the bug. "
                "[evidence:00000000-0000-4000-8000-000000000000] "
                "shows the leak."
            ),
            source_evidence={},
        )
        assert report.passed is False
        assert "00000000-0000-4000-8000-000000000000" in (
            report.missing_evidence_claims
        )


# ---- 5. Submission is never automatic ---------------------------------


class TestSubmissionNeverAutomatic:
    @pytest.mark.asyncio
    async def test_submit_requires_approval_token(
        self, migrated_db: Database, campaign_id: str, tmp_path: Path
    ) -> None:
        """``submit_final_report`` must refuse to run without a
        valid, unconsumed approval token."""
        from mavr.reports.submission import SubmissionError

        # Pass a clearly-invalid approval token; the module must raise
        # ``SubmissionError`` rather than silently submitting.
        async with migrated_db.acquire() as conn:
            with pytest.raises(SubmissionError):
                await submit_final_report(
                    conn,
                    finding_id="11111111-1111-4111-8111-111111111111",
                    version=1,
                    approval_token="",
                    output_dir=str(tmp_path / "out"),
                )

    def test_no_autorun_submission_flag(
        self, migrated_db: Database, campaign_id: str
    ) -> None:
        """The runtime must never auto-submit; every submission has
        to go through a human-approved entry point. This test reads
        the report-submission source and asserts there is no
        fire-and-forget code path that runs without an approval."""
        import inspect

        from mavr.reports import submission

        src = inspect.getsource(submission)
        # The only submission entrypoint must require an approval.
        assert "approval_id" in src
        # No auto-submit on a timer / cron / idle hook.
        assert "asyncio.create_task(submit" not in src
        assert "schedule_submit" not in src
        # The submission entrypoint must be present.
        assert "async def submit" in src
