"""Model-context budgeting before routing (issue #170, PLAN §7).

Estimates whether a task fits a model's context window *before* routing,
and splits oversized tasks into ordered subtasks that each fit. Pure
token-arithmetic policy: the actual token count is unknowable without a
tokenizer per provider, so estimation uses a conservative chars-per-token
ratio — better to split one task too many than to blow a window mid-run.

Guarantee semantics: ``plan_for_model`` either returns a plan whose every
chunk satisfies (estimated input + reserved output) <= context window, or
raises :class:`ContextBudgetError` with an actionable reason. Callers get
an output-length guarantee by construction: ``reserved_output`` tokens are
subtracted up front and reported back so dispatch can enforce them.
"""

from __future__ import annotations

from dataclasses import dataclass

# Conservative default: ~4 chars/token for English + code. Deliberately
# under-estimates token capacity slightly so estimates err toward splitting.
DEFAULT_CHARS_PER_TOKEN = 4.0


class ContextBudgetError(ValueError):
    """A task cannot be routed to a model within its context budget."""


@dataclass(frozen=True)
class BudgetCheck:
    """Result of checking one text against one model's limits."""

    estimated_input_tokens: int
    reserved_output_tokens: int
    context_window: int
    fits: bool
    reason: str = ""


@dataclass(frozen=True)
class TaskPlan:
    """An ordered split of a task that fits the target model's window."""

    model_key: str
    chunks: tuple[str, ...]
    reserved_output_tokens: int
    estimated_input_tokens_per_chunk: int  # max across chunks


def estimate_tokens(text: str, chars_per_token: float = DEFAULT_CHARS_PER_TOKEN) -> int:
    """Conservative token estimate; empty text costs nothing."""
    if chars_per_token <= 0:
        raise ValueError("chars_per_token must be positive")
    return int(len(text) / chars_per_token)


def check_budget(
    prompt: str,
    context_window: int,
    reserved_output: int,
    chars_per_token: float = DEFAULT_CHARS_PER_TOKEN,
) -> BudgetCheck:
    """Does prompt + reserved output fit inside the context window?"""
    if context_window <= 0:
        return BudgetCheck(
            0,
            reserved_output,
            context_window,
            False,
            "context window unknown (0) — cannot guarantee budget",
        )
    if reserved_output < 0 or reserved_output >= context_window:
        return BudgetCheck(
            estimate_tokens(prompt, chars_per_token),
            reserved_output,
            context_window,
            False,
            f"reserved output {reserved_output} must be in [0, context_window)",
        )
    est = estimate_tokens(prompt, chars_per_token)
    if est + reserved_output > context_window:
        return BudgetCheck(
            est,
            reserved_output,
            context_window,
            False,
            f"estimated input {est} + reserved output {reserved_output} "
            f"exceeds context window {context_window}",
        )
    return BudgetCheck(est, reserved_output, context_window, True)


def plan_for_model(
    task_text: str,
    context_window: int,
    reserved_output: int,
    min_chunk_chars: int = 200,
    chars_per_token: float = DEFAULT_CHARS_PER_TOKEN,
) -> TaskPlan:
    """Split *task_text* into ordered chunks that each fit the window.

    Splitting strategy: fixed-size character windows sized from the token
    budget, with an explicit continuation marker prepended to non-first
    chunks so downstream agents know the chunk is partial (continuity is
    preserved by order; markers make it explicit). Raises if even one
    minimal chunk cannot fit — that means the window is unusable for any
    real work and routing must pick another model.
    """
    check = check_budget(task_text, context_window, reserved_output, chars_per_token)
    usable_chars = int((context_window - reserved_output) * chars_per_token)
    if usable_chars < min_chunk_chars:
        raise ContextBudgetError(
            f"context window {context_window} minus reserved output "
            f"{reserved_output} leaves <{min_chunk_chars} chars of input room — "
            "model cannot accept this task class"
        )

    # If it already fits, no split needed.
    if check.fits:
        return TaskPlan(
            model_key="",
            chunks=(task_text,),
            reserved_output_tokens=reserved_output,
            estimated_input_tokens_per_chunk=check.estimated_input_tokens,
        )

    marker = "[continued] "
    chunk_len = usable_chars - len(marker)
    chunks = []
    for start in range(0, len(task_text), chunk_len):
        piece = task_text[start : start + chunk_len]
        if start > 0:
            piece = marker + piece
        chunks.append(piece)

    worst = max(estimate_tokens(c, chars_per_token) for c in chunks)
    # Guard against arithmetic drift (marker overhead at tiny budgets).
    if worst + reserved_output > context_window:
        raise ContextBudgetError("split chunks still exceed budget — shrink min_chunk_chars")
    return TaskPlan(
        model_key="",
        chunks=tuple(chunks),
        reserved_output_tokens=reserved_output,
        estimated_input_tokens_per_chunk=worst,
    )


def plan_with_catalog(
    catalog_entry,
    task_text: str,
    output_share: float = 0.25,
    chars_per_token: float = DEFAULT_CHARS_PER_TOKEN,
) -> TaskPlan:
    """Build a plan from a providers.model_catalog CatalogEntry.

    ``output_share`` reserves that fraction of the context window for the
    model's output, bounded above by the entry's declared max_output_tokens
    when known (>0). Unknown windows raise rather than guess: routing into
    an unknown-size window is how runs die mid-task.
    """
    window = getattr(catalog_entry, "context_window", 0)
    if window <= 0:
        raise ContextBudgetError(
            f"{getattr(catalog_entry, 'key', 'entry')}: context window unknown — "
            "cannot budget; mark the model unroutable or supply a window"
        )
    max_out = getattr(catalog_entry, "max_output_tokens", 0) or 0
    reserved = min(int(window * output_share), max_out) if max_out else int(window * output_share)
    plan = plan_for_model(task_text, window, reserved, chars_per_token=chars_per_token)
    return TaskPlan(
        model_key=getattr(catalog_entry, "key", ""),
        chunks=plan.chunks,
        reserved_output_tokens=plan.reserved_output_tokens,
        estimated_input_tokens_per_chunk=plan.estimated_input_tokens_per_chunk,
    )
