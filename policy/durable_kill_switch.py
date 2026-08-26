"""Durability layer for the global kill switch (PLAN §15; issue #65).

:class:`policy.kill_switch.KillSwitch` is process-local — correct within one
run, but a crash/restart after activation would silently come back up armed,
which §15 forbids ("a killed system stays killed until explicitly re-armed").
:class:`DurableKillSwitch` adds the missing persistence:

- The engaged state (with reason + timestamp) is written to a small JSON
  state file with fsync **before** the in-process latch flips, so a crash at
  any point cannot produce "in-memory off / on-disk on" ambiguity that gets
  resolved the wrong way: disk wins at startup.
- On construction the switch re-reads the state file; if it records an
  engagement, the fresh process starts already active — restart-while-killed
  stays killed.
- ``rearm()`` is the only way back: operator-explicit, returns whether this
  call actually cleared a persisted engagement, and clears the reason so a
  stale reason can't leak into a later activation's audit trail.

The in-memory ``KillSwitch`` semantics (latching, callbacks, gate) are
inherited unchanged — this class only layers load/save around them.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

from policy.kill_switch import KillSwitch


class DurableKillSwitch(KillSwitch):
    """Kill switch whose engaged state survives process restarts."""

    STATE_VERSION = 1

    def __init__(self, state_path: str | Path):
        self.state_path = Path(state_path)
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        super().__init__()
        self._load_or_initialize()

    # --- persistence -----------------------------------------------------

    def _write_state(self, engaged: bool, reason: str = "") -> None:
        # Write-temp-then-rename with fsync: a crash mid-write can never leave
        # a half-written state file that reads as disengaged (the dangerous
        # direction). Rename is atomic on POSIX.
        tmp = self.state_path.with_suffix(".tmp")
        payload = {
            "version": self.STATE_VERSION,
            "engaged": engaged,
            "reason": reason,
            "updated_at": time.time(),
        }
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(payload, f, sort_keys=True)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self.state_path)

    def _load_or_initialize(self) -> None:
        if not self.state_path.exists():
            # First run: persist the disengaged baseline so every later read
            # has an authoritative file rather than "absence means safe".
            self._write_state(engaged=False)
            return
        try:
            data = json.loads(self.state_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            # Corrupt state file: fail CLOSED. A safety control must never let
            # a damaged file silently re-arm the system.
            data = {"engaged": True, "reason": "corrupt kill-switch state file"}
        if data.get("engaged"):
            # Restart while killed: restore the latch without re-running
            # activation callbacks (those are for live tasks; none exist yet).
            self._reason = str(data.get("reason", ""))
            self._event.set()

    # --- overrides -------------------------------------------------------

    def activate(self, reason: str = "") -> bool:
        """Persist BEFORE flipping the latch: if we crash between the write
        and the flag set, startup sees 'engaged' and stays killed — never the
        reverse."""
        with self._lock:
            already = self._event.is_set()
        if not already:
            self._write_state(engaged=True, reason=reason)
        return super().activate(reason=reason)

    def deactivate(self) -> None:
        raise RuntimeError(
            "DurableKillSwitch.deactivate() is disabled: use rearm(actor=...), "
            "which persists the cleared state and is audited by the caller."
        )

    def rearm(self, actor: str = "") -> bool:
        """Operator-explicit re-arm. Returns True if a persisted engagement
        was actually cleared. Callers must append the audit event themselves
        (Controls.rearm_kill_switch does)."""
        with self._lock:
            was_active = self._event.is_set()
            self._reason = ""
            self._event.clear()
        self._write_state(engaged=False)
        return was_active
