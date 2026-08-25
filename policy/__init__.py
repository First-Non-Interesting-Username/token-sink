"""Policy & safety layer: scope enforcement, tool-call gating, SSRF protections (PLAN §5, §15).

Human controls (kill switch, pause/resume/stop, approvals, audit log) live in
the sibling modules; see docs/human-controls.md (issue #30).
"""

from .controls import ControlAction, ControlError
from .kill_switch import KillSwitch, KillSwitchActive

__all__ = [
    "ControlAction",
    "ControlError",
    "KillSwitch",
    "KillSwitchActive",
]
