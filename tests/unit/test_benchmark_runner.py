"""Mock-provider tests for the benchmark runner (issue #86, PLAN §8.4)."""

from __future__ import annotations

import json
import uuid

import pytest

from evaluation.benchmark_cli import build_parser
from evaluation.benchmark_cli import main as cli_main
from evaluation.benchmarks import SUITE, SUITE_VERSION, Category, items_for
from evaluation.runner import BenchmarkRun, CompletionResult, ItemResult
from schemas.validate import SchemaRegistry


def _uuid() -> str:
    return str(uuid.uuid4())


def _mock_completion(responses: dict[str, str] | None = None):
    """Deterministic mock: keyed responses, sensible JSON defaults otherwise."""

    def complete(prompt: str) -> CompletionResult:
        if responses and prompt in responses:
            raw = responses[prompt]
        elif "Respond ONLY with JSON" in prompt or "ONLY with JSON matching" in prompt:
            # Build a schema-valid record for the two JSON tasks.
            if '"record_type": "task"' in prompt:
                raw = json.dumps(
                    {
                        "schema_version": 1,
                        "record_type": "task",
                        "task_uuid": _uuid(),
                        "campaign_uuid": _uuid(),
                        "kind": "recon",
                        "status": "pending",
                        "created_at": "2026-08-25T12:00:00Z",
                    }
                )
            else:
                raw = json.dumps(
                    {
                        "schema_version": 1,
                        "record_type": "review",
                        "review_uuid": _uuid(),
                        "finding_uuid": _uuid(),
                        "campaign_uuid": _uuid(),
                        "phase": "first_review",
                        "reviewer_provenance": {"agent_uuid": _uuid(), "role": "reviewer"},
                        "conclusion": "confirmed",
                        "created_at": "2026-08-25T12:00:00Z",
                    }
                )
        elif "syllogism" in prompt.lower() or "premises" in prompt.lower():
            raw = (
                "No — we cannot conclude that some red team members write "
                "reports. The premises only guarantee analysts write reports; "
                "the subset relationship does not transfer."
            )
        elif "seven" in prompt:
            raw = "seven"
        else:
            raw = (
                "The logging hygiene problem is writing the secret credential "
                "token into logs, exposing sensitive data."
            )
        return CompletionResult(raw_output=raw, input_tokens=10, output_tokens=20)

    return complete


@pytest.fixture()
def registry() -> SchemaRegistry:
    return SchemaRegistry()


class TestSuiteDefinition:
    def test_suite_is_versioned_and_nonempty(self) -> None:
        assert SUITE_VERSION >= 1 and len(SUITE) >= 4

    def test_categories_covered(self) -> None:
        cats = {t.category for t in SUITE.values()}
        assert {Category.REASONING, Category.STRUCTURED_OUTPUT, Category.TOOL_USE} <= cats

    def test_filter_by_category(self) -> None:
        assert all(t.category == Category.REASONING for t in items_for(Category.REASONING))


class TestRunnerExecute:
    def test_full_run_all_pass_with_good_mock(self, registry: SchemaRegistry) -> None:
        run = BenchmarkRun(
            provider_id="mock",
            model_id="good-model",
            completion=_mock_completion(),
            free_only=False,
        )
        results = run.execute(registry=registry)
        assert len(results) == len(SUITE)
        assert all(r.passed for r in results), [r.check_details for r in results]

    def test_malformed_output_fails_not_coerced(self, registry: SchemaRegistry) -> None:
        bad = _mock_completion()
        run = BenchmarkRun(
            provider_id="mock",
            model_id="sloppy-model",
            completion=lambda p: bad(p),
            free_only=False,
        )

        def broken(prompt: str) -> CompletionResult:
            if "record_type" in prompt and "JSON" in prompt:
                return CompletionResult(raw_output='{"schema_version": 1, "record_typ')  # truncated
            return bad(prompt)

        run.completion = broken
        results = run.execute(registry=registry)
        json_items = [r for r in results if r.category == "structured_output"]
        tool_items = [r for r in results if r.category == "tool_use"]
        assert all(not r.passed for r in json_items + tool_items)
        assert any("schema:" in d for r in results for d in r.check_details)

    def test_adapter_exception_fails_item_not_run(self, registry: SchemaRegistry) -> None:
        def boom(prompt: str) -> CompletionResult:
            raise TimeoutError("upstream timeout")

        run = BenchmarkRun("mock", "dead", boom, free_only=False)
        results = run.execute(registry=registry)
        assert len(results) == len(SUITE)
        assert all(not r.passed and "TimeoutError" in r.error for r in results)

    def test_records_usage_and_latency(self, registry: SchemaRegistry) -> None:
        run = BenchmarkRun("mock", "m", _mock_completion(), free_only=False)
        (r,) = [x for x in run.execute(registry=registry) if x.item_id == "reasoning-counting"]
        assert r.input_tokens > 0 and r.output_tokens > 0 and r.latency_ms >= 0


class TestFreeOnlyGate:
    @pytest.mark.parametrize("status", ["paid", "unknown", None])
    def test_unknown_or_paid_refused(self, status: str | None, registry: SchemaRegistry) -> None:
        run = BenchmarkRun("gateway", "gpt-x", _mock_completion(), free_only=True)
        catalog = {"gpt-x": status} if status else {}
        with pytest.raises(ValueError, match="not confirmed free"):
            run.execute(registry=registry, catalog_free_status=catalog)

    def test_confirmed_free_allowed(self, registry: SchemaRegistry) -> None:
        run = BenchmarkRun("gateway", "free-m", _mock_completion(), free_only=True)
        results = run.execute(registry=registry, catalog_free_status={"free-m": "free"})
        assert len(results) == len(SUITE)


class TestResumability:
    def test_resume_skips_completed_items(self, registry: SchemaRegistry) -> None:
        first = BenchmarkRun("mock", "m", _mock_completion(), free_only=False)
        partial = {
            t.item_id: ItemResult(
                run_id=first.run_id,
                item_id=t.item_id,
                category=t.category.value,
                passed=True,
                quality_score=1.0,
                latency_ms=1,
                input_tokens=1,
                output_tokens=1,
            )
            for t in items_for()[:2]
        }
        first.resume(partial)
        calls: list[str] = []

        def counting(prompt: str) -> CompletionResult:
            calls.append(prompt)
            return _mock_completion()(prompt)

        first.completion = counting
        results = first.execute(registry=registry)
        assert len(results) == len(SUITE)
        # Only the remaining items hit the model — no double-counting.
        assert len(calls) == len(SUITE) - 2
        assert {r.item_id for r in results[:2]} == set(partial)


class TestCli:
    def test_dry_run_lists_items_without_model(self, capsys: pytest.CaptureFixture) -> None:
        rc = cli_main(["--model", "m", "--provider", "p", "--dry-run"])
        out = capsys.readouterr().out
        assert rc == 0 and "reasoning-counting" in out

    def test_free_only_default_blocks_paid(self) -> None:
        rc = cli_main(["--model", "m", "--provider", "p"])
        assert rc == 2  # refused under free-only, not silently benchmarked

    def test_parser_accepts_expected_flags(self) -> None:
        args = build_parser().parse_args(
            [
                "--model",
                "m",
                "--provider",
                "p",
                "--category",
                "reasoning",
                "--suite-version",
                "1",
                "--dry-run",
                "--concurrency",
                "2",
            ]
        )
        assert args.concurrency == 2 and args.dry_run
