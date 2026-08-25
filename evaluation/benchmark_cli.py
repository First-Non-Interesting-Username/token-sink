"""`system model benchmark` CLI (PLAN §17, issue #86).

Wires the benchmark runner into a CLI surface. Provider adapters are not
wired yet (#14 in flight), so this module exposes the argument parsing and
orchestration around a completion-callable factory — real adapters plug in
via `make_completion_fn`.
"""

from __future__ import annotations

import argparse
import json

from evaluation.benchmarks import Category, items_for
from evaluation.runner import BenchmarkRun, CompletionFn, ItemResult


def make_completion_fn(provider_id: str, model_id: str) -> CompletionFn:
    """Return a completion callable for a provider/model pair.

    Placeholder until provider adapters land (#14): raises so callers get a
    clear error instead of silently benchmarking nothing.
    """
    raise NotImplementedError(
        f"provider adapters not wired yet (#14); cannot benchmark {provider_id}/{model_id} yet"
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="system model benchmark")
    parser.add_argument("--model", required=True, help="model id to benchmark")
    parser.add_argument("--provider", required=True, help="provider id to benchmark")
    parser.add_argument(
        "--category",
        choices=[c.value for c in Category],
        help="restrict to one score category",
    )
    parser.add_argument("--suite-version", type=int, default=None, help=argparse.SUPPRESS)
    parser.add_argument("--dry-run", action="store_true", help="list items; call no model")
    parser.add_argument("--concurrency", type=int, default=1, help="max parallel benchmark items")
    parser.add_argument(
        "--allow-paid",
        action="store_true",
        help="permit benchmarking paid/unknown-status models (free-only by default)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    category = Category(args.category) if args.category else None

    if args.dry_run:
        # No completion fn needed; never touches free-only gating.
        for t in items_for(category):
            print(f"{t.item_id}\t{t.category.value}")
        return 0

    run = BenchmarkRun(
        provider_id=args.provider,
        model_id=args.model,
        concurrency=max(1, args.concurrency),
        free_only=not args.allow_paid,
    )
    # Free-only gate BEFORE any adapter construction: a paid/unknown-status
    # model is refused outright (§8.2, #66).
    try:
        run.ensure_free_confirmed()  # no catalog wired yet → unknown ⇒ refused
        run.completion = _resolve_completion(args)
        results: list[ItemResult] = run.execute(category=category)
    except ValueError as exc:
        print(f"error: {exc}", file=__import__("sys").stderr)
        return 2
    for r in results:
        status = "PASS" if r.passed else "FAIL"
        print(
            json.dumps(
                {
                    "item": r.item_id,
                    "category": r.category,
                    "status": status,
                    "quality_score": r.quality_score,
                    "latency_ms": r.latency_ms,
                    "tokens_in": r.input_tokens,
                    "tokens_out": r.output_tokens,
                }
            )
        )
    return 0 if all(r.passed for r in results) and results else 1


def _resolve_completion(args: argparse.Namespace) -> CompletionFn:
    return make_completion_fn(args.provider, args.model)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
