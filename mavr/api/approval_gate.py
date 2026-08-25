"""Approval gate for active testing and submissions (spec §10, §17).

The gate is consulted by API endpoints that perform privileged
operations (active testing, PoC execution against a live target,
submission, scope change, deletion). It returns a structured error if
the caller has not presented a valid approval token. The gate also
records a metric counter on every check so the UI can render the
approval rate.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from fastapi import HTTPException, status

from mavr import approvals as approvals_mod
from mavr.observability.metrics import MetricsStore
from mavr.storage.database import Database


@dataclass(frozen=True)
class GateResult:
    approval: approvals_mod.Approval
    remaining_seconds: int


class ApprovalGate:
    def __init__(self, db: Database, metrics: MetricsStore | None = None) -> None:
        self._db = db
        self._metrics = metrics

    async def require(
        self,
        *,
        action: str,
        token: str,
        campaign_id: str | None = None,
        finding_id: str | None = None,
    ) -> GateResult:
        if not token:
            await self._record(action, allowed=False, reason="missing")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"approval token required for {action}",
            )
        try:
            async with self._db.acquire() as conn:
                approval = await approvals_mod.consume(
                    conn,
                    token=token,
                    expected_action=action,
                )
        except approvals_mod.ApprovalError as exc:
            await self._record(action, allowed=False, reason=str(exc))
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=str(exc),
            ) from exc
        if campaign_id is not None and approval.campaign_id and approval.campaign_id != campaign_id:
            await self._record(action, allowed=False, reason="campaign_mismatch")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="approval token was issued for a different campaign",
            )
        if finding_id is not None and approval.finding_id and approval.finding_id != finding_id:
            await self._record(action, allowed=False, reason="finding_mismatch")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="approval token was issued for a different finding",
            )
        remaining = max(0, int((approval.expires_at - datetime.now(UTC)).total_seconds()))
        await self._record(action, allowed=True, reason="ok")
        return GateResult(approval=approval, remaining_seconds=remaining)

    async def _record(self, action: str, *, allowed: bool, reason: str) -> None:
        if self._metrics is None:
            return
        try:
            await self._metrics.inc_counter(
                "approval.gate",
                dimensions={"action": action, "allowed": "1" if allowed else "0", "reason": reason},
                is_free=True,
                is_paid=False,
            )
        except Exception:  # noqa: BLE001
            # metrics are best-effort; never break the gate
            pass


__all__ = ["ApprovalGate", "GateResult"]
