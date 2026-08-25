"""Evaluation fixtures (PLAN §19.4).

Synthetic, self-contained finding records used to evaluate the review
pipeline (#11/#13) and feed the safety suite (#26) and score system (#17).

Every fixture is a dict matching the shape the finding lifecycle state
machine consumes (see PLAN.md §10/§11): a finding record plus its evidence
and review history. Nothing here references real targets, credentials, or
secrets — all domains use RFC 2606 reserved names (example.com etc.).

Categories, per issue #47 / §19.4:

- ``true_positive``    — findings with ground-truth evidence they are real
- ``false_positive``   — findings that look plausible but are demonstrably wrong
- ``ambiguous``        — reviewer disagreement is the expected outcome
- ``conflicting_reviews`` — review histories where reviewers split
- ``adversarial_provider_response`` — malformed or injection-bearing model output
"""

from __future__ import annotations

import json
from pathlib import Path

FIXTURES_DIR = Path(__file__).parent

_CATEGORIES = (
    "true_positive",
    "false_positive",
    "ambiguous",
    "conflicting_reviews",
    "adversarial_provider_response",
)

_cache: dict[str, list[dict]] = {}


def load_category(category: str) -> list[dict]:
    """Return all fixtures in a category.

    Raises ValueError for unknown categories so typos fail loudly in tests
    instead of silently evaluating against an empty set.
    """
    if category not in _CATEGORIES:
        raise ValueError(f"unknown fixture category: {category!r} (known: {_CATEGORIES})")
    if category not in _cache:
        # Fixtures are tiny; read-through cache keeps repeat loads cheap in CI.
        path = FIXTURES_DIR / f"{category}.json"
        _cache[category] = json.loads(path.read_text(encoding="utf-8"))
    return [json.loads(json.dumps(f)) for f in _cache[category]]


def load_all() -> list[dict]:
    """Return every fixture across all categories."""
    out: list[dict] = []
    for cat in _CATEGORIES:
        out.extend(load_category(cat))
    return out


def categories() -> tuple[str, ...]:
    return _CATEGORIES
