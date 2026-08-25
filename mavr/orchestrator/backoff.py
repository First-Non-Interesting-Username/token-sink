"""Backoff helpers for retry scheduling.

Used by the agent runtime to space retries with full jitter, and by
the queue sweeper to schedule lease reclamation.
"""
from __future__ import annotations

import random
from dataclasses import dataclass


@dataclass(frozen=True)
class BackoffPolicy:
    initial_seconds: float = 1.0
    max_seconds: float = 60.0
    multiplier: float = 2.0
    jitter: float = 0.25  # +/- 25% multiplicative jitter

    def __post_init__(self) -> None:
        if self.initial_seconds <= 0:
            raise ValueError("initial_seconds must be > 0")
        if self.max_seconds < self.initial_seconds:
            raise ValueError("max_seconds must be >= initial_seconds")
        if self.multiplier < 1.0:
            raise ValueError("multiplier must be >= 1.0")
        if not (0.0 <= self.jitter < 1.0):
            raise ValueError("jitter must be in [0, 1)")

    def delay_for(self, attempt: int) -> float:
        """Return seconds to wait before retry ``attempt`` (1-indexed)."""
        if attempt < 1:
            attempt = 1
        base = self.initial_seconds * (self.multiplier ** (attempt - 1))
        base = min(base, self.max_seconds)
        spread = base * self.jitter
        return max(0.0, random.uniform(base - spread, base + spread))
