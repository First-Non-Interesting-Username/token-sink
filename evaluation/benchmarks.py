"""Versioned benchmark suite definition (PLAN §8.4).

A small, non-sensitive set of representative tasks per model-score category
(§8.3). Each task pairs a prompt with the schema its output must validate
against and automated checks that produce a quality score. Human/multi-agent
evaluation hooks are optional per run (§8.4) — a run can be fully automated.

The suite is versioned: results record the suite version so scores from
different suites are never mixed (§17 imports them as initial priors only;
they must not override live performance measurements).
"""

from __future__ import annotations

import enum
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

# Bump when task content or checks change incompatibly; results are keyed on
# this so old priors stay distinguishable.
SUITE_VERSION = 1


class Category(enum.Enum):
    """Score categories from §8.3 that have benchmark tasks."""

    LATENCY = "latency"
    REASONING = "reasoning"
    STRUCTURED_OUTPUT = "structured_output"
    TOOL_USE = "tool_use"
    SECURITY_ANALYSIS = "security_analysis"


@dataclass(frozen=True)
class CheckResult:
    """One automated check's outcome for one item."""

    name: str
    passed: bool
    detail: str = ""


@dataclass(frozen=True)
class BenchTask:
    """One benchmark task (§8.4): prompt + expected schema + automated checks.

    `expected_schema_name` names a schema under schemas/ (e.g. "task") that
    the raw completion must satisfy — structured-output reliability is itself
    a scored category, so malformed output fails rather than coerces.
    """

    item_id: str
    category: Category
    prompt: str
    expected_schema_name: str | None  # None → no schema gate for this task
    # Automated checks receive the parsed payload (or None if unparseable)
    # and return their verdicts. Kept as callables so tasks stay data-light.
    checks: tuple[Callable[[Any], list[CheckResult]], ...] = field(default_factory=tuple)

    def run_checks(self, payload: Any) -> list[CheckResult]:
        results: list[CheckResult] = []
        for check in self.checks:
            results.extend(check(payload))
        return results


def _contains_all(*needles: str) -> Callable[[Any], list[CheckResult]]:
    def check(payload: Any) -> list[CheckResult]:
        text = payload if isinstance(payload, str) else ""
        missing = [n for n in needles if n.lower() not in text.lower()]
        return [
            CheckResult(
                name="contains_expected_terms",
                passed=not missing,
                detail=f"missing: {missing}" if missing else "",
            )
        ]

    return check


def _min_length(n: int) -> Callable[[Any], list[CheckResult]]:
    def check(payload: Any) -> list[CheckResult]:
        ok = isinstance(payload, str) and len(payload) >= n
        length = len(payload) if isinstance(payload, str) else -1
        return [CheckResult(name="min_length", passed=ok, detail=f"len={length}")]

    return check


# --- The versioned suite ---------------------------------------------------
#
# Tasks are deliberately generic and non-sensitive (§8.4): no live targets,
# no real findings, nothing operational. They exercise response shape,
# instruction-following, and reasoning enough to seed initial routing priors.
SUITE: dict[str, BenchTask] = {
    t.item_id: t
    for t in (
        BenchTask(
            item_id="reasoning-basic-syllogism",
            category=Category.REASONING,
            prompt=(
                "Answer in one short paragraph. Premises: all red team members "
                "are analysts; some analysts write reports. Question: can we "
                "conclude some red team members write reports? Explain why or "
                "why not."
            ),
            expected_schema_name=None,
            checks=(_contains_all("cannot", "not"), _min_length(40)),
        ),
        BenchTask(
            item_id="reasoning-counting",
            category=Category.REASONING,
            prompt="Reply with exactly the word seven spelled out, nothing else.",
            expected_schema_name=None,
            checks=(_contains_all("seven"),),
        ),
        BenchTask(
            item_id="security-analysis-static",
            category=Category.SECURITY_ANALYSIS,
            prompt=(
                "Given this snippet of pseudocode: `token = request.args['t']; "
                "log('token=' + token)` — name the logging hygiene problem in "
                "one sentence."
            ),
            expected_schema_name=None,
            checks=(_contains_all("secret", "credential", "sensitive"), _min_length(20)),
        ),
        BenchTask(
            item_id="tool-use-plan-shape",
            category=Category.TOOL_USE,
            prompt=(
                "You are planning a reconnaissance step. Respond ONLY with JSON: "
                '{"schema_version": 1, "record_type": "task", "task_uuid": "<uuid>", '
                '"campaign_uuid": "<uuid>", "kind": "recon", "status": "pending", '
                '"created_at": "<rfc3339>"} — use valid values.'
            ),
            expected_schema_name="task",
            checks=(),
        ),
        BenchTask(
            item_id="structured-output-review",
            category=Category.STRUCTURED_OUTPUT,
            prompt=(
                "Respond ONLY with JSON matching this shape: "
                '{"schema_version": 1, "record_type": "review", "review_uuid": "<uuid>", '
                '"finding_uuid": "<uuid>", "campaign_uuid": "<uuid>", '
                '"phase": "first_review", "reviewer_provenance": {"agent_uuid": "<uuid>", '
                '"role": "reviewer"}, "conclusion": "confirmed", "created_at": "<rfc3339>"}'
            ),
            expected_schema_name="review",
            checks=(),
        ),
    )
}


def items_for(category: Category | None = None) -> list[BenchTask]:
    """Suite items, optionally filtered to one category."""
    return [t for t in SUITE.values() if category is None or t.category == category]
