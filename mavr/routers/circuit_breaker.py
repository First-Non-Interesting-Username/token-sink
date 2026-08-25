"""Circuit breaker for provider/model pairs.

Implements a simple closed/open/half-open state machine:

* ``closed`` — normal operation
* ``open`` — failures crossed the threshold; the breaker is open for
  ``cooldown_seconds`` and refuses all calls
* ``half_open`` — after the cooldown, a single probe call is allowed;
  success closes the breaker, failure re-opens it

The state is persisted in the ``circuit_breakers`` table so that a
restarted router can pick up exactly where the previous one left off.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from mavr.observability.logging import get_logger
from mavr.schemas.routing import CircuitBreakerState, CircuitState
from mavr.storage.database import Database

log = get_logger(__name__)


@dataclass
class BreakerConfig:
    failure_threshold: int = 3
    success_threshold: int = 1
    cooldown_seconds: int = 60


class CircuitBreakerStore:
    def __init__(self, db: Database, config: BreakerConfig | None = None) -> None:
        self._db = db
        self._config = config or BreakerConfig()

    @property
    def config(self) -> BreakerConfig:
        return self._config

    async def get(self, provider_id: str, model_key: str) -> CircuitBreakerState:
        row = await self._db.fetchone(
            """
            SELECT provider_id, model_key, state, failures, successes,
                   opened_at, cooldown_until, last_failure_at, last_error
            FROM circuit_breakers
            WHERE provider_id = ? AND model_key = ?
            """,
            (provider_id, model_key),
        )
        if row is None:
            return CircuitBreakerState(provider_id=provider_id, model_key=model_key)
        return _row_to_state(row)

    async def record_success(self, provider_id: str, model_key: str) -> CircuitBreakerState:
        state = await self.get(provider_id, model_key)
        if state.state == CircuitState.HALF_OPEN:
            state.successes += 1
            if state.successes >= self._config.success_threshold:
                state.state = CircuitState.CLOSED
                state.failures = 0
                state.successes = 0
                state.opened_at = None
                state.cooldown_until = None
        else:
            state.successes += 1
            state.failures = 0
        await self._upsert(state)
        return state

    async def record_failure(
        self, provider_id: str, model_key: str, error: str
    ) -> CircuitBreakerState:
        state = await self.get(provider_id, model_key)
        state.failures += 1
        state.successes = 0
        state.last_failure_at = datetime.now(UTC)
        state.last_error = (error or "")[:512]
        if state.failures >= self._config.failure_threshold:
            state.state = CircuitState.OPEN
            state.opened_at = datetime.now(UTC)
            state.cooldown_until = state.opened_at + timedelta(seconds=self._config.cooldown_seconds)
            log.warning(
                "circuit_open",
                provider_id=provider_id,
                model_key=model_key,
                failures=state.failures,
                cooldown_until=state.cooldown_until.isoformat(),
            )
        await self._upsert(state)
        # After persisting, check whether a probe is allowed.
        if state.state == CircuitState.OPEN and _cooldown_elapsed(state):
            state.state = CircuitState.HALF_OPEN
            await self._upsert(state)
        return state

    async def allow(self, provider_id: str, model_key: str) -> bool:
        state = await self.get(provider_id, model_key)
        if state.state == CircuitState.CLOSED:
            return True
        if state.state == CircuitState.HALF_OPEN:
            return True
        # state == open
        if state.cooldown_until and _cooldown_elapsed(state):
            await self._half_open(provider_id, model_key)
            return True
        return False

    async def _half_open(self, provider_id: str, model_key: str) -> None:
        await self._db.execute(
            """
            UPDATE circuit_breakers
            SET state = 'half_open'
            WHERE provider_id = ? AND model_key = ?
            """,
            (provider_id, model_key),
        )

    async def _upsert(self, state: CircuitBreakerState) -> None:
        await self._db.execute(
            """
            INSERT INTO circuit_breakers(
                id, schema_version, provider_id, model_key, state,
                failures, successes, opened_at, cooldown_until,
                last_failure_at, last_error
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(provider_id, model_key) DO UPDATE SET
                state = excluded.state,
                failures = excluded.failures,
                successes = excluded.successes,
                opened_at = excluded.opened_at,
                cooldown_until = excluded.cooldown_until,
                last_failure_at = excluded.last_failure_at,
                last_error = excluded.last_error
            """,
            (
                _new_id(),
                "1.0.0",
                state.provider_id,
                state.model_key,
                state.state.value,
                int(state.failures),
                int(state.successes),
                state.opened_at.isoformat() if state.opened_at else None,
                state.cooldown_until.isoformat() if state.cooldown_until else None,
                state.last_failure_at.isoformat() if state.last_failure_at else None,
                state.last_error,
            ),
        )


# ---- helpers ------------------------------------------------------------


def _cooldown_elapsed(state: CircuitBreakerState) -> bool:
    if state.cooldown_until is None:
        return True
    return datetime.now(UTC) >= state.cooldown_until


def _row_to_state(row: Any) -> CircuitBreakerState:
    return CircuitBreakerState(
        provider_id=row["provider_id"],
        model_key=row["model_key"],
        state=CircuitState(row["state"]),
        failures=int(row["failures"]),
        successes=int(row["successes"]),
        opened_at=datetime.fromisoformat(row["opened_at"]) if row["opened_at"] else None,
        cooldown_until=datetime.fromisoformat(row["cooldown_until"]) if row["cooldown_until"] else None,
        last_failure_at=datetime.fromisoformat(row["last_failure_at"]) if row["last_failure_at"] else None,
        last_error=row["last_error"] or "",
    )


def _new_id() -> str:
    import uuid

    return str(uuid.uuid4())
