"""CLI launch and control of the local web UI server (issue #306, PLAN §21 DoD).

Design decisions (per AGENTS.md "document everything"):

- **Thin surface over existing subsystems.** The server itself is a small
  stdlib ``http.server`` app (no new dependencies — same choice as
  ``api/approvals.py``) that serves a minimal dashboard page on GET and
  hardens every request with ``api.security.guard_request`` (issue #152's
  loopback/Host/Origin/bearer defenses). The CLI does not re-implement any
  of that; it composes it.

- **Process control via pidfile.** ``token-sink webui start`` launches the
  server as a detached background process and records its PID + port in a
  state file under the system temp dir. ``status`` reads that file and
  probes the HTTP endpoint; ``stop`` terminates the process. This is what
  "the CLI reliably launches and controls the local web UI" means in
  practice: start → status reports healthy URL → stop actually stops.

- **Fail closed on port conflicts and stale state.** A port already in use
  raises before the state file is written; a state file pointing at a dead
  or foreign PID is reported as ``stopped`` and cleaned up rather than
  trusted.

- **Deterministic core, thin I/O shell.** All logic lives in pure functions
  over an explicit state directory so tests run without spawning real
  daemons except where the behavior under test *is* daemon lifecycle.
"""

from __future__ import annotations

import json
import os
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

STATE_FILE = "webui-state.json"


class WebUiError(RuntimeError):
    """Raised for operator-facing failures (port busy, already running…)."""


@dataclass(frozen=True)
class WebUiState:
    pid: int
    port: int
    token: str
    url: str

    def to_json(self) -> str:
        return json.dumps(
            {"pid": self.pid, "port": self.port, "url": self.url, "token": self.token}
        )

    @staticmethod
    def from_json(text: str) -> WebUiState:
        d = json.loads(text)
        return WebUiState(pid=d["pid"], port=d["port"], url=d["url"], token=d["token"])


def default_state_dir() -> Path:
    return Path(tempfile.gettempdir()) / "token-sink-webui"


def read_state(state_dir: Path) -> WebUiState | None:
    path = state_dir / STATE_FILE
    if not path.exists():
        return None
    try:
        return WebUiState.from_json(path.read_text())
    except (ValueError, KeyError):
        return None


def write_state(state_dir: Path, state: WebUiState) -> None:
    state_dir.mkdir(parents=True, exist_ok=True)
    (state_dir / STATE_FILE).write_text(state.to_json())


def clear_state(state_dir: Path) -> None:
    (state_dir / STATE_FILE).unlink(missing_ok=True)


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True  # exists but owned by someone else
    return True


def http_ok(url: str, timeout: float = 2.0) -> bool:
    """True if GET <url> returns any HTTP response at all."""
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            return resp.status == 200
    except (urllib.error.URLError, OSError):
        return False


def probe(state: WebUiState | None) -> tuple[str, str]:
    """Classify current runtime state → ('running'|'stopped', human detail)."""
    if state is None:
        return "stopped", "not started"
    if not _pid_alive(state.pid):
        return "stopped", f"stale state: pid {state.pid} no longer exists"
    if not http_ok(state.url):
        return "stopped", f"pid {state.pid} alive but not answering on {state.url}"
    return "running", f"healthy at {state.url} (pid {state.pid})"


def find_free_port(host: str = "127.0.0.1") -> int:
    with socket.socket() as s:
        s.bind((host, 0))
        return s.getsockname()[1]


def start(state_dir: Path, host: str = "127.0.0.1", port: int = 0) -> WebUiState:
    """Launch the web UI as a detached background process; returns its state."""
    kind, detail = probe(read_state(state_dir))
    if kind == "running":
        raise WebUiError(f"web UI already running: {detail}")

    from api.security import generate_session_token
    from ui.server import create_server

    chosen_port = port or find_free_port(host)
    # Fail fast on an explicit busy port before detaching anything.
    try:
        srv = create_server(host=host, port=chosen_port)
    except OSError as exc:
        raise WebUiError(f"cannot bind {host}:{chosen_port}: {exc}") from exc
    actual_port = srv.server_address[1]

    token = generate_session_token()
    state_dir.mkdir(parents=True, exist_ok=True)
    log_file = state_dir / "webui.log"

    script = (
        "import sys; sys.path[:0] = ['.', 'src'];"
        "from cli.webui import serve_forever;"
        f"serve_forever({actual_port!r}, {host!r}, {token!r})"
    )
    proc = subprocess.Popen(
        [sys.executable, "-c", script],
        cwd=str(Path(__file__).resolve().parent.parent),
        stdout=open(log_file, "ab"),
        stderr=subprocess.STDOUT,
        start_new_session=True,  # detach: survives the CLI exiting
    )
    srv.server_close()  # child binds its own socket

    state = WebUiState(
        pid=proc.pid,
        port=actual_port,
        token=token,
        url=f"http://{host}:{actual_port}",
    )
    write_state(state_dir, state)

    # Reliability contract: don't report success until the child answers HTTP.
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        if http_ok(state.url, timeout=1.0):
            return state
        if proc.poll() is not None:
            clear_state(state_dir)
            raise WebUiError(
                f"web UI process exited immediately (code {proc.returncode}); see {log_file}"
            )
        time.sleep(0.1)
    stop(state_dir)
    raise WebUiError("web UI did not become ready within 5s; aborted")


def serve_forever(port: int, host: str, token: str) -> None:
    """Entry point of the detached child process."""
    from ui.server import create_server

    srv = create_server(host=host, port=port, token=token)
    try:
        srv.serve_forever()
    finally:
        srv.server_close()


def stop(state_dir: Path) -> str:
    """Terminate the running web UI; tolerant of already-stopped state."""
    state = read_state(state_dir)
    if state is None:
        return "stopped (was not running)"
    clear_state(state_dir)
    if not _pid_alive(state.pid):
        return f"stopped (cleaned stale state for pid {state.pid})"
    try:
        os.kill(state.pid, signal.SIGTERM)
    except ProcessLookupError:
        return "stopped (process vanished)"
    deadline = time.monotonic() + 5.0
    while _pid_alive(state.pid) and time.monotonic() < deadline:
        time.sleep(0.05)
    else:
        if _pid_alive(state.pid):
            os.kill(state.pid, signal.SIGKILL)
    return f"stopped (pid {state.pid} terminated)"


def status(state_dir: Path) -> tuple[str, str]:
    kind, detail = probe(read_state(state_dir))
    return kind, detail


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(prog="token-sink webui")
    sub = parser.add_subparsers(dest="command", required=True)
    start_p = sub.add_parser("start", help="launch the local web UI")
    start_p.add_argument("--host", default="127.0.0.1")
    start_p.add_argument("--port", type=int, default=0, help="0 = pick a free port")
    start_p.add_argument("--state-dir", default=None)
    status_p = sub.add_parser("status", help="report whether the web UI is running")
    status_p.add_argument("--state-dir", default=None)
    stop_p = sub.add_parser("stop", help="terminate the web UI")
    stop_p.add_argument("--state-dir", default=None)
    args = parser.parse_args(argv)
    state_dir = Path(args.state_dir) if getattr(args, "state_dir", None) else default_state_dir()

    if args.command == "start":
        try:
            state = start(state_dir, host=args.host, port=args.port)
        except WebUiError as exc:
            print(f"error: {exc}")
            return 1
        print(f"web UI running: {state.url}")
        print(f"session token (needed for mutating requests): {state.token}")
        return 0
    if args.command == "status":
        kind, detail = status(state_dir)
        print(f"{kind}: {detail}")
        return 0 if kind == "running" else 3
    return 0 if "stopped" in stop(state_dir) else 1
