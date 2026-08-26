"""Local web-UI HTTP server (issue #306, PLAN §13/§21).

A minimal stdlib ``http.server`` application — no new dependencies, same
choice as ``api/approvals.py`` and ``fixtures/target/server.py``. It serves
a dashboard page on GET and delegates *all* request hardening to
``api.security.guard_request`` (issue #152): Host validation, Origin
validation on mutating methods, and per-launch bearer token on every
non-GET request. This module deliberately contains zero security logic of
its own — one choke point, already tested.
"""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from api.security import guard_request

_DASHBOARD = json.dumps(
    {
        "app": "token-sink web UI",
        "views": ["dashboard", "agents", "findings", "approvals"],
        "status": "ok",
    }
).encode()


def create_server(
    host: str = "127.0.0.1",
    port: int = 0,
    token: str | None = None,
) -> ThreadingHTTPServer:
    """Bind the hardened UI server; returns it unstarted unless asked."""
    if token is None:
        from api.security import generate_session_token

        token = generate_session_token()
    server = _UiServer((host, port), _make_handler(token))
    return server


class _UiServer(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True


def _make_handler(token: str):
    class Handler(BaseHTTPRequestHandler):
        def _dispatch(self) -> None:
            headers = {k: v for k, v in self.headers.items()}
            verdict = guard_request(self.command, headers, expected_token=token)
            if not verdict.allowed:
                body = json.dumps({"error": verdict.reason}).encode()
                self.send_response(verdict.status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return

            if self.path.startswith("/api/"):
                # API surface placeholder: real views land via their own issues.
                body = json.dumps({"error": "not found"}).encode()
                status = 404
            else:
                body = _DASHBOARD
                status = 200
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = _dispatch

        def log_message(self, format, *args):  # noqa: A002 - stdlib signature
            pass  # keep CLI/test output clean

    return Handler
