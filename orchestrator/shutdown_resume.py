"""Campaign shutdown checkpoints & restart resumption (issue #138, PLAN §12).

``orchestrator.shutdown`` (#136) provides the generic drain/intent/recovery
protocol. This module adds the *campaign-level* resumption layer on top:

- :class:`ShutdownCheckpoint` — the durable record of what was in flight when
  the process stopped: per-agent last completed step, pending task IDs, and
  the event-store position (Last-Event-ID) so resume continues exactly where
  the stream stopped.
- :class:`CampaignShutdownManager` — writes the checkpoint plus a
  **clean-stop marker** during graceful drain. The marker's presence is what
  distinguishes a clean ``system stop`` from a crash for postmortems.
- :func:`resume_campaign` — startup recovery: detect an unclean stop (missing
  marker), requeue the checkpointed tasks and emit an operator-visible
  :class:`ResumeReport` of what was resumed vs requeued.

No duplicated work across a restart: task ids are reused verbatim, so the
idempotency journal (:mod:`orchestrator.idempotency`, #245/#126) dedupes any
step that actually completed before the crash — the requeue is safe by
construction, not by bookkeeping hope.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

CHECKPOINT_FILE = "campaign_checkpoint.json"
CLEAN_STOP_MARKER = "shutdown_complete.marker"


class CheckpointError(RuntimeError):
    """A checkpoint is corrupt or unreadable; recovery must refuse to guess."""


@dataclass
class ShutdownCheckpoint:
    """What was in flight at stop time — written before exit, read on boot."""

    campaign_uuid: str
    agent_steps: dict[str, str] = field(default_factory=dict)  # agent → last completed step
    pending_task_ids: list[str] = field(default_factory=list)
    event_stream_position: int = 0  # Last-Event-ID for event-store replay (#42/#31)
    clean_stop: bool = False
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": 1,
            "campaign_uuid": self.campaign_uuid,
            "agent_steps": dict(self.agent_steps),
            "pending_task_ids": list(self.pending_task_ids),
            "event_stream_position": self.event_stream_position,
            "clean_stop": self.clean_stop,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> ShutdownCheckpoint:
        if d.get("version") != 1:
            raise CheckpointError(f"unknown checkpoint version: {d.get('version')!r}")
        return cls(
            campaign_uuid=d["campaign_uuid"],
            agent_steps={str(k): str(v) for k, v in d.get("agent_steps", {}).items()},
            pending_task_ids=[str(t) for t in d.get("pending_task_ids", [])],
            event_stream_position=int(d.get("event_stream_position", 0)),
            clean_stop=bool(d.get("clean_stop", False)),
            created_at=float(d.get("created_at", 0.0)),
        )


def _write_atomic(path: Path, text: str) -> None:
    """Write via temp+rename so a crash mid-write can't tear the file."""
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    tmp.replace(path)


class CampaignShutdownManager:
    """Coordinates checkpoint writing during graceful drain."""

    def __init__(self, state_dir: str | Path):
        self.state_dir = Path(state_dir)
        self.state_dir.mkdir(parents=True, exist_ok=True)

    @property
    def _checkpoint_path(self) -> Path:
        return self.state_dir / CHECKPOINT_FILE

    @property
    def _marker_path(self) -> Path:
        return self.state_dir / CLEAN_STOP_MARKER

    def write_checkpoint(
        self,
        campaign_uuid: str,
        *,
        agent_steps: dict[str, str] | None = None,
        pending_task_ids: list[str] | None = None,
        event_stream_position: int = 0,
        clean_stop: bool,
    ) -> ShutdownCheckpoint:
        """Persist one checkpoint atomically, then drop the clean-stop marker.

        Order matters: the checkpoint lands first, the marker second. A crash
        between them leaves a checkpoint with no marker = 'interrupted', which
        is exactly what recovery should assume.
        """
        cp = ShutdownCheckpoint(
            campaign_uuid=campaign_uuid,
            agent_steps=agent_steps or {},
            pending_task_ids=pending_task_ids or [],
            event_stream_position=event_stream_position,
            clean_stop=clean_stop,
        )
        _write_atomic(self._checkpoint_path, json.dumps(cp.to_dict(), indent=2))
        if clean_stop:
            _write_atomic(self._marker_path, cp.campaign_uuid)
        else:
            self._marker_path.unlink(missing_ok=True)
        return cp

    def load_checkpoint(self) -> ShutdownCheckpoint | None:
        """Read the last checkpoint; None when nothing was ever written."""
        if not self._checkpoint_path.exists():
            return None
        try:
            return ShutdownCheckpoint.from_dict(
                json.loads(self._checkpoint_path.read_text(encoding="utf-8"))
            )
        except (ValueError, KeyError, TypeError) as exc:
            raise CheckpointError(f"corrupt checkpoint: {exc}") from exc

    def was_clean_stop(self) -> bool:
        return self._marker_path.exists()

    def clear_state(self) -> None:
        """Drop checkpoint + marker after successful resume (idempotent)."""
        self._checkpoint_path.unlink(missing_ok=True)
        self._marker_path.unlink(missing_ok=True)


@dataclass
class ResumeReport:
    """Operator-visible summary of what a restart picked up (§12/§21)."""

    campaign_uuid: str
    interrupted: bool  # False = clean stop, nothing dramatic happened
    resumed_task_ids: list[str] = field(default_factory=list)
    requeued_task_ids: list[str] = field(default_factory=list)
    skipped_done_task_ids: list[str] = field(default_factory=list)  # already completed pre-crash

    def summary(self) -> str:
        kind = "unclean interruption" if self.interrupted else "clean stop"
        return (
            f"resume after {kind} of campaign {self.campaign_uuid}: "
            f"{len(self.resumed_task_ids)} in-flight resumed, "
            f"{len(self.requeued_task_ids)} requeued, "
            f"{len(self.skipped_done_task_ids)} already complete (skipped)"
        )


def resume_campaign(
    manager: CampaignShutdownManager,
    *,
    done_tasks: set[str],
    requeue: Any,  # Callable[[str], None]
) -> ResumeReport:
    """Recover after restart: classify checkpointed tasks and requeue live ones.

    ``done_tasks`` — task ids known to have completed before the stop (the
    caller reads this from the idempotency journal), which are skipped.
    ``requeue(task_id)`` — callback that puts a task back on the queue with its
    ORIGINAL id; journal-level idempotency keys make re-execution safe even
    for tasks whose effects partially applied before the crash.

    State files are cleared afterwards so a double-restart is a no-op, and an
    explicit CheckpointError propagates rather than guessing.
    """
    cp = manager.load_checkpoint()
    if cp is None:
        raise CheckpointError("no checkpoint found; nothing to resume")

    report = ResumeReport(
        campaign_uuid=cp.campaign_uuid,
        interrupted=not manager.was_clean_stop(),
    )
    for task_id in cp.pending_task_ids:
        if task_id in done_tasks:
            report.skipped_done_task_ids.append(task_id)
            continue
        requeue(task_id)
        report.requeued_task_ids.append(task_id)
        report.resumed_task_ids.append(task_id)

    manager.clear_state()
    return report
