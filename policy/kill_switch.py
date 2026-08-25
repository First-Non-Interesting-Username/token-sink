"""Global kill switch (PLAN.md §15).

Activation is a latched, process-wide atomic flag: once on, every network
action gate must refuse and all active tasks are reported as cancelled.
Deactivation is deliberate and audited — an operator action, never an
automatic timeout — because a safety control that silently re-enables itself
is worse than one that stays off.
"""

from __future__ import annotations

import threading
from collections.abc import Callable


class KillSwitchActive(RuntimeError):
    """Raised when a gated action is attempted while the kill switch is on."""


class KillSwitch:
    """Process-global kill switch. All network/tool egress must route through
    `check()` or `gate()` so activation immediately stops new actions."""

    def __init__(self) -> None:
        self._event = threading.Event()
        self._lock = threading.Lock()
        self._callbacks: list[Callable[[str], None]] = []
        self._reason = ""

    @property
    def active(self) -> bool:
        return self._event.is_set()

    @property
    def reason(self) -> str:
        return self._reason

    def activate(self, reason: str = "") -> bool:
        """Latch the switch on. Returns True if this call flipped it."""
        with self._lock:
            already = self._event.is_set()
            if not already:
                # Set reason before flipping the flag so observers never see
                # active=True with an empty/missing reason.
                self._reason = reason
                self._event.set()
            callbacks = list(self._callbacks)
        if not already:
            for cb in callbacks:
                cb(reason)
        return not already

    def deactivate(self) -> None:
        """Operator-explicit reset. Callers must audit this themselves."""
        with self._lock:
            self._reason = ""
            self._event.clear()

    def check(self, action: str = "") -> None:
        """Raise KillSwitchActive if the switch is engaged."""
        if self._event.is_set():
            detail = f" for action '{action}'" if action else ""
            raise KillSwitchActive(f"kill switch engaged{detail}: no new network actions permitted")

    def gate(self, fn: Callable) -> Callable:
        """Decorator/wrapper: refuse wrapped calls while engaged."""

        def wrapper(*args, **kwargs):
            self.check(getattr(fn, "__name__", ""))
            return fn(*args, **kwargs)

        return wrapper

    def on_activate(self, cb: Callable[[str], None]) -> Callable[[str], None]:
        """Register a callback invoked once at activation. Used by runtimes to
        cancel in-flight tasks; must not raise into the activator's path."""
        with self._lock:
            self._callbacks.append(cb)
        return cb

    def cancel_active_tasks(self) -> int:
        """Invoke cancellation hooks; returns number of tasks cancelled.

        Kept separate from activate() so callers can audit both steps, but
        Controls.activate_kill_switch wires them together automatically.
        """
        with self._lock:
            callbacks = list(self._callbacks)
            n = len(callbacks)
        for cb in callbacks:
            try:
                cb(self._reason)
            except Exception:
                # Cancellation hooks must never prevent other hooks from
                # running — fail-safe, not fail-deadly.
                pass
        return n
