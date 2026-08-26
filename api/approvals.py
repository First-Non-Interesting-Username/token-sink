"""Approval-center REST API (issue #206, PLAN §13.6 view 6, §15).

A thin, stdlib-only HTTP surface over ``policy.approvals.ApprovalBackend``:
the backend already owns the lifecycle state machine and writes every
transition to the hash-chained AuditLog — this layer must never mutate
request state directly, only through backend methods, so the audit trail
proves every decision.

Endpoints::

    GET    /approvals              → list (default: pending queue)
    GET    /approvals/<id>         → one request
    POST   /approvals/<id>/approve {"decided_by": ..., "reason": ...}
    POST   /approvals/<id>/reject  {"decided_by": ..., "reason": ...}

Design choices:
- loopback-only binding by default: this API can grant live-target
  execution, so it must not be reachable off-host (same posture as the
  local web UI hardening tracked in issue #152).
- No new dependencies: stdlib ``http.server``, like fixtures/target.
- Errors are structured JSON so the UI can render them without parsing
  strings; unknown IDs map to 404, invalid transitions to 409.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from policy.approvals import ApprovalBackend, ApprovalError


class ApprovalApiServer:
    """HTTP server exposing the pending-approval queue and decisions."""

    def __init__(self, backend: ApprovalBackend, host: str = "127.0.0.1", port: int = 0):
        # host defaults to loopback: approval grants gate live-target
        # actions, so remote reachability would be a safety regression.
        self.backend = backend
        self._host = host
        self._port = port
        self._httpd: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    # -- request handling (kept separate for unit testing) -------------------

    def handle(self, method: str, path: str, body: bytes = b"") -> tuple[int, dict]:
        """Route one logical request; returns (status, json_body)."""
        parts = [p for p in path.strip("/").split("/") if p]
        try:
            payload = json.loads(body) if body else {}
            if not isinstance(payload, dict):
                raise ValueError("body must be a JSON object")
        except (ValueError, UnicodeDecodeError) as exc:
            return 400, {"error": f"invalid JSON body: {exc}"}

        if method == "GET" and parts == ["approvals"]:
            return 200, {"requests": [self._serialize(r) for r in self.backend.pending()]}
        if len(parts) >= 2 and parts[0] == "approvals":
            approval_id = parts[1]
            try:
                req = self.backend.get(approval_id)
            except ApprovalError:
                return 404, {"error": f"unknown approval {approval_id}"}
            if method == "GET" and len(parts) == 2:
                return 200, self._serialize(req)
            action = parts[2] if len(parts) == 3 else ""
            if method != "POST" or action not in ("approve", "reject"):
                return 405, {"error": "use GET /approvals/<id> or POST .../approve|/reject"}
            decided_by = str(payload.get("decided_by") or "").strip()
            if not decided_by:
                # Decisions are audited with an actor; anonymous approvals
                # would make the trail unverifiable, so they're refused.
                return 400, {"error": "decided_by is required"}
            reason = str(payload.get("reason") or "")
            try:
                if action == "approve":
                    req = self.backend.grant(
                        approval_id, decided_by=decided_by, decision_reason=reason
                    )
                else:
                    req = self.backend.deny(
                        approval_id, decided_by=decided_by, decision_reason=reason
                    )
            except ApprovalError as exc:
                # e.g. approving a denied/expired request: a state conflict,
                # not a client bug — 409 tells the UI to refresh its view.
                return 409, {"error": str(exc), "state": req.state.value}
            return 200, self._serialize(req)
        return 404, {"error": f"no route for {method} {path}"}

    @staticmethod
    def _serialize(req) -> dict:
        return {
            "id": req.id,
            "action": req.action,
            "subject": req.subject,
            "requested_by": req.requested_by,
            "campaign_id": req.campaign_id,
            "policy_rule": req.policy_rule,
            "payload_snapshot": req.payload_snapshot,
            "reason": req.reason,
            "created_at": req.created_at.isoformat(),
            "expires_at": req.expires_at.isoformat() if req.expires_at else None,
            "single_use": req.single_use,
            "state": req.state.value,
            "decided_by": req.decided_by,
            "decision_reason": req.decision_reason,
        }

    # -- server lifecycle ------------------------------------------------------

    def start(self) -> str:
        server = self

        class Handler(BaseHTTPRequestHandler):
            def _dispatch(self) -> None:
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length) if length else b""
                status, out = server.handle(self.command, self.path, body)
                data = json.dumps(out).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            do_GET = do_POST = _dispatch

            def log_message(self, format, *args):  # noqa: A002 - stdlib signature
                pass  # keep test output clean

        self._httpd = ThreadingHTTPServer((self._host, self._port), Handler)
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()
        return f"http://{self._host}:{self._httpd.server_address[1]}"

    def stop(self) -> None:
        if self._httpd:
            self._httpd.shutdown()
            self._httpd.server_close()
            self._httpd = None
