"""Benchmark runner (PLAN §8.4, issue #86).

Executes the versioned suite (`evaluation/benchmarks.py`) against selected
provider/model pairs and records first-class results that the score system
(#17) imports as initial priors. Benchmarks inform initial routing only —
they must never override live performance measurements afterwards (§8.4).

Design:

- The runner takes a pluggable completion callable
  ``Callable[[str], CompletionResult]`` so tests run against mocks and real
  provider adapters wire in later without touching this module.
- Runs are resumable and idempotent: each item's result is keyed by
  ``(run_id, item_id)``; re-invoking a crashed run via ``resume()`` skips
  already-completed items instead of double-counting.
- Free-only constraints (#66) are honored structurally: when ``free_only``
  is set, models whose catalog free-status is not confirmed 'free' (paid OR
  unknown, including missing metadata per §8.2) are refused outright.
"""

from __future__ import annotations

import json
import time
import uuid
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

from evaluation.benchmarks import SUITE_VERSION, BenchTask, Category, items_for
from schemas.validate import SchemaRegistry


@dataclass(frozen=True)
class CompletionResult:
    """One model response plus usage metadata from the adapter."""

    raw_output: str
    input_tokens: int = 0
    output_tokens: int = 0


# Signature adapters must satisfy to be benchmarkable.
CompletionFn = Callable[[str], CompletionResult]


@dataclass(frozen=True)
class ItemResult:
    """Per-item outcome, recorded per §8.4."""

    run_id: str
    item_id: str
    category: str
    passed: bool
    quality_score: float  # 0..1 across automated checks + schema gate
    latency_ms: int
    input_tokens: int
    output_tokens: int
    check_details: list[str] = field(default_factory=list)
    error: str = ""


@dataclass
class BenchmarkRun:
    """A resumable, idempotent benchmark run for one provider/model pair."""

    provider_id: str
    model_id: str
    completion: CompletionFn | None = None
    run_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    free_only: bool = True
    concurrency: int = 1
    suite_version: int = SUITE_VERSION
    # item_id -> ItemResult; persisted state for resume-after-crash.
    completed: dict[str, ItemResult] = field(default_factory=dict)

    def resume(self, prior_results: dict[str, ItemResult]) -> None:
        """Load results from an interrupted execution of this run.

        Idempotency contract: items present here are skipped by execute(),
        so a crashed run continues without double-counting.
        """
        self.completed.update(prior_results)

    def ensure_free_confirmed(self, catalog_free_status: dict[str, str] | None = None) -> None:
        """Pre-flight free-only gate (#66): raise unless model is confirmed free."""
        if not self.free_only:
            return
        status = (catalog_free_status or {}).get(self.model_id)
        if status != "free":
            raise ValueError(
                f"model {self.model_id!r} not confirmed free "
                f"(status={status!r}); refusing benchmark under free-only"
            )

    def execute(
        self,
        category: Category | None = None,
        dry_run: bool = False,
        registry: SchemaRegistry | None = None,
        catalog_free_status: dict[str, str] | None = None,
    ) -> list[ItemResult]:
        """Run all remaining suite items; returns the full result set.

        - category: restrict to one §8.3 category.
        - dry_run: list what would run without calling the model.
        - free_only (constructor): refuse models whose catalog entry is not
          confirmed 'free' (#66; unknown ⇒ excluded until confirmed).
        """
        if self.free_only:
            self.ensure_free_confirmed(catalog_free_status)

        tasks = [t for t in items_for(category) if t.item_id not in self.completed]
        if dry_run:
            return []

        registry = registry or SchemaRegistry()
        assert self.completion is not None, "no completion fn set (dry run?)"
        completion = self.completion
        workers = max(1, min(self.concurrency, len(tasks))) if tasks else 1
        with ThreadPoolExecutor(max_workers=workers) as pool:
            new_results = list(
                pool.map(lambda t: _run_item(registry, t, completion, self.run_id), tasks)
            )
        for r in new_results:
            self.completed[r.item_id] = r
        return sorted(self.completed.values(), key=lambda r: r.item_id)


def _run_item(
    registry: SchemaRegistry,
    task: BenchTask,
    completion: CompletionFn,
    run_id: str,
) -> ItemResult:
    """Execute + score one item. Adapter errors fail the item, never crash the run."""
    start = time.monotonic()
    try:
        comp = completion(task.prompt)
    except Exception as exc:
        return ItemResult(
            run_id=run_id,
            item_id=task.item_id,
            category=task.category.value,
            passed=False,
            quality_score=0.0,
            latency_ms=int((time.monotonic() - start) * 1000),
            input_tokens=0,
            output_tokens=0,
            error=f"{type(exc).__name__}: {exc}",
        )
    latency_ms = int((time.monotonic() - start) * 1000)

    details: list[str] = []
    total = 0.0
    count = 0

    # Schema gate first (§18 ordering: cheap structural check drives the
    # headline structured-output reliability signal). Malformed output fails;
    # it is never coerced.
    if task.expected_schema_name is not None:
        _, vr = _classify(comp.raw_output, task.expected_schema_name, registry)
        count += 1
        if vr.valid:
            total += 1.0
        else:
            details.extend(f"schema: {e}" for e in vr.errors[:3])

    payload: object
    try:
        payload = json.loads(comp.raw_output.strip())
    except (json.JSONDecodeError, ValueError):
        payload = comp.raw_output.strip()
    for cr in task.run_checks(payload):
        count += 1
        if cr.passed:
            total += 1.0
        else:
            details.append(f"{cr.name}: {cr.detail}")

    score = round(total / count, 3) if count else 0.0
    return ItemResult(
        run_id=run_id,
        item_id=task.item_id,
        category=task.category.value,
        passed=count > 0 and score >= 1.0,
        quality_score=score,
        latency_ms=latency_ms,
        input_tokens=comp.input_tokens,
        output_tokens=comp.output_tokens,
        check_details=details,
    )


def _classify(raw: str, record_type: str, registry: SchemaRegistry):
    from schemas.validate import classify_result  # local to avoid import cycle at module load

    return classify_result(raw, record_type, registry)
