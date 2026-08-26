"""Live agent activity view API (issue #169, PLAN §13.2 view 2).

A thin, stdlib-only HTTP surface over ``ui.activity_board.AgentActivityBoard``
(the in-memory queryable snapshot of agent state, fed by orchestrator events).
Same posture as ``api/approvals.py``: loopback-only binding by default — this
surface exposes agent UUIDs, tasks and tool metadata that must not leak
off-host; redaction of tool-call payloads follows observability.logs.

Endpoints::

    GET /agents                     → board snapshot (filters via query string:
                                      campaign, role, status)
    GET /agents/<uuid>              → one agent card + task history

Design choices:
- No new dependencies: stdlib ``http.server``, matching the other api/ modules.
- The board never mutates agent state; it renders what event handlers report.
- Stale agents (heartbeat older than the stale threshold) are flagged inline so
  the UI can render heartbeat warnings without extra endpoints.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from ui.activity_board import AgentActivityBoard


class AgentActivityApiServer:
    """HTTP server exposing the live agent grid."""

    def __init__(self, board: AgentActivityBoard, host: str = "127.0.0.1", port: int = 0):
        # loopback default: agent/task/tool metadata is internal operational
        # data (issue #152 posture) — never bind off-host by accident.
        self.board = board
        self._host = host
        self._port = port
        self._httpd: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    # -- request handling (separate from socket layer for unit testing) ------

    def handle(self, method: str, path: str, body: bytes = b"") -> tuple[int, dict]:
        parts = [p for p in path.strip("/").split("/") if p]
        if method != "GET":
            return 405, {"error": "activity view is read-only"}
        try:
            payload = json.loads(body) if body else {}
        except (ValueError, UnicodeDecodeError):
            return 400, {"error": "invalid JSON body"}

        if len(parts) == 1 and parts[0] == "agents":
            filters = payload.get("filters", {})
            return 200, {
                "agents": [
                    self.board.card(a)
                    for a in self.board.snapshot(
                        campaign=filters.get("campaign"),
                        role=filters.get("role"),
                        status=filters.get("status"),
                    )
                ],
                "generated_at": self.board.now_iso(),
                "stale_threshold_s": self.board.stale_threshold_s,
            }
        if len(parts) == 2 and parts[0] == "agents":
            card = self.board.drilldown(parts[1])
            if card is None:
                return 404, {"error": f"unknown agent {parts[1]!r}"}
            return 200, card
        return 404, {"error": "unknown route"}

    # -- server lifecycle -----------------------------------------------------

    def start(self) -> int:
        httpd = ThreadingHTTPServer((self._host, self._port), self._make_handler())
        self._httpd = httpd
        self._thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        self._thread.start()
        return httpd.server_address[1]

    def stop(self) -> None:
        if self._httpd:
            self._httpd.shutdown()
            self._httpd.server_close()
            self._httpd = None
        if self._thread:
            self._thread.join(timeout=5)
            self._thread = None

    def _make_handler(self):
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802 (stdlib naming)
                status, payload = outer.handle("GET", self.path)
                self._respond(status, payload)

            def log_message(self, *args) -> None:  # silence stderr noise
                pass

            def _respond(self, status: int, payload: dict) -> None:
                data = json.dumps(payload).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        return Handler
