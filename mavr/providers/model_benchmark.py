"""Offline model benchmark (spec §8.3).

A small, self-contained suite of prompts per task category. Each
``BenchmarkPrompt`` carries a structured check that the harness runs
against the response. No sensitive data ever lives here — the prompts
are short, public, and replaceable.

The suite is versioned; results are persisted in ``benchmark_runs`` and
``benchmark_results`` so that score evolution is auditable.
"""
from __future__ import annotations

import json
import time
from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from mavr.observability.logging import get_logger
from mavr.providers.model_catalog.scores import ModelScoreStore
from mavr.schemas.routing import (
    BenchmarkPrompt,
    ChatMessage,
    ChatRequest,
    ChatResponse,
    TaskCategory,
)
from mavr.storage.database import Database

log = get_logger(__name__)

SUITE_VERSION = "2026-01-15"


# ---- prompt sets per category ------------------------------------------


SECURITY_REVIEW_PROMPTS: list[BenchmarkPrompt] = [
    BenchmarkPrompt(
        id="rev-001",
        category=TaskCategory.REVIEW,
        messages=[
            ChatMessage(
                role="system",
                content=(
                    "You are a security review assistant. Reply with 'accept' "
                    "or 'reject' on a single line, then one short reason."
                ),
            ),
            ChatMessage(
                role="user",
                content=(
                    "Review this finding: SQL injection in /api/users via the "
                    "raw concatenation of the `id` query parameter. The endpoint "
                    "is publicly reachable. Is this a valid high-severity finding?"
                ),
            ),
        ],
        must_contain=["reject"],  # we expect the model to flag the wording
        max_tokens=200,
    ),
    BenchmarkPrompt(
        id="rev-002",
        category=TaskCategory.REVIEW,
        messages=[
            ChatMessage(
                role="system",
                content="You are a security review assistant. Answer 'yes' or 'no' only.",
            ),
            ChatMessage(
                role="user",
                content=(
                    "Does a missing rate limiter on a public login endpoint "
                    "constitute a vulnerability? Reply with exactly 'yes' or 'no'."
                ),
            ),
        ],
        must_contain=["yes"],
        max_tokens=20,
    ),
]


DISCOVERY_PROMPTS: list[BenchmarkPrompt] = [
    BenchmarkPrompt(
        id="disc-001",
        category=TaskCategory.DISCOVERY,
        messages=[
            ChatMessage(
                role="system",
                content="List 3 common classes of web vulnerabilities. One per line.",
            ),
            ChatMessage(
                role="user",
                content="Give me 3 categories, comma-separated.",
            ),
        ],
        must_contain=["XSS", "SQL", "CSRF"],
        max_tokens=120,
    ),
]


POLISH_PROMPTS: list[BenchmarkPrompt] = [
    BenchmarkPrompt(
        id="pol-001",
        category=TaskCategory.POLISH,
        messages=[
            ChatMessage(
                role="system",
                content=(
                    "You reword technical findings into clear prose. Keep the "
                    "word 'vulnerability' in your response."
                ),
            ),
            ChatMessage(
                role="user",
                content="Reword: 'Reflected XSS via q param. Severity medium.'",
            ),
        ],
        must_contain=["vulnerability"],
        max_tokens=120,
    ),
]


CATEGORY_PROMPTS: dict[TaskCategory, list[BenchmarkPrompt]] = {
    TaskCategory.REVIEW: SECURITY_REVIEW_PROMPTS,
    TaskCategory.DISCOVERY: DISCOVERY_PROMPTS,
    TaskCategory.POLISH: POLISH_PROMPTS,
    # other categories share the generic harness; their prompts are
    # added in their own beads.
}


def all_prompts() -> list[BenchmarkPrompt]:
    out: list[BenchmarkPrompt] = []
    for prompts in CATEGORY_PROMPTS.values():
        out.extend(prompts)
    return out


def prompts_for(category: TaskCategory) -> list[BenchmarkPrompt]:
    return list(CATEGORY_PROMPTS.get(category, []))


# ---- runner ------------------------------------------------------------


class BenchmarkRunner:
    """Run the offline benchmark suite against one or more adapters."""

    def __init__(self, db: Database, score_store: ModelScoreStore) -> None:
        self._db = db
        self._scores = score_store

    async def run(
        self,
        targets: Iterable[tuple[str, str, ChatFn]],
        *,
        actor_kind: str = "human",
        actor_id: str | None = None,
        notes: str = "",
    ) -> str:
        """Run the suite. ``targets`` is a sequence of ``(provider_id, model_key, chat_fn)`` tuples.

        ``chat_fn(model_key, request)`` should mirror
        :meth:`ProviderAdapter.chat` for testing. Returns the run id.
        """
        run_id = str(uuid4())
        now = _now_iso()
        await self._db.execute(
            """
            INSERT INTO benchmark_runs(
                id, schema_version, suite_version, started_at,
                actor_kind, actor_id, config_snapshot, summary, notes
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                run_id,
                "1.0.0",
                SUITE_VERSION,
                now,
                actor_kind,
                actor_id,
                "{}",
                "{}",
                notes,
            ),
        )

        summary: dict[str, Any] = {"results": 0, "passed": 0, "by_model": {}}
        for provider_id, model_key, chat_fn in targets:
            for prompt in all_prompts():
                passed, score, duration_ms, error = await self._execute_one(
                    chat_fn, provider_id, model_key, prompt
                )
                await self._db.execute(
                    """
                    INSERT INTO benchmark_results(
                        id, schema_version, run_id, provider_id, model_key,
                        category, prompt_id, passed, score, duration_ms,
                        error, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        str(uuid4()),
                        "1.0.0",
                        run_id,
                        provider_id,
                        model_key,
                        prompt.category.value,
                        prompt.id,
                        1 if passed else 0,
                        float(score),
                        int(duration_ms),
                        error,
                        _now_iso(),
                    ),
                )
                summary["results"] += 1
                if passed:
                    summary["passed"] += 1
                key = f"{provider_id}/{model_key}"
                bucket = summary["by_model"].setdefault(key, {"passed": 0, "total": 0})
                bucket["total"] += 1
                if passed:
                    bucket["passed"] += 1
                # update the per-(model, category) score
                await self._scores.update_from_samples(
                    provider_id,
                    model_key,
                    prompt.category,
                    [score],
                    source="benchmark",
                )

        # finalize the run
        await self._db.execute(
            "UPDATE benchmark_runs SET finished_at = ?, summary = ? WHERE id = ?",
            (_now_iso(), json.dumps(summary, sort_keys=True), run_id),
        )
        log.info(
            "benchmark_run_complete",
            run_id=run_id,
            suite_version=SUITE_VERSION,
            results=summary["results"],
            passed=summary["passed"],
        )
        return run_id

    async def _execute_one(
        self,
        chat_fn: ChatFn,
        provider_id: str,
        model_key: str,
        prompt: BenchmarkPrompt,
    ) -> tuple[bool, float, int, str | None]:
        request = ChatRequest(
            messages=prompt.messages,
            max_tokens=prompt.max_tokens or 200,
        )
        start = time.monotonic()
        try:
            response: ChatResponse = await chat_fn(model_key, request)
        except Exception as exc:  # noqa: BLE001 — capture any error
            duration = int((time.monotonic() - start) * 1000)
            log.warning(
                "benchmark_prompt_error",
                provider=provider_id,
                model=model_key,
                prompt=prompt.id,
                error=str(exc),
            )
            return False, 0.0, duration, str(exc)
        duration = int((time.monotonic() - start) * 1000)
        ok = _check_response(response.content, prompt)
        score = 1.0 if ok else 0.0
        return ok, score, duration, None


# ---- helpers ------------------------------------------------------------


def _check_response(content: str, prompt: BenchmarkPrompt) -> bool:
    """Run a simple substring check against the prompt's structured expectation.

    Real benchmark suites will use richer checks (JSON shape, regex
    match, etc.); this scaffolding supports both ``must_contain`` and
    ``must_not_contain`` as the initial contract.
    """
    text = (content or "").strip()
    if not text:
        return False
    for needle in prompt.must_contain:
        if needle.lower() not in text.lower():
            return False
    for needle in prompt.must_not_contain:
        if needle.lower() in text.lower():
            return False
    return True


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


# Type alias used by the runner. Defined here so callers don't need to
# import the adapter module.
ChatFn = Any
