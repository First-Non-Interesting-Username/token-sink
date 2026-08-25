"""The mock-target HTTP server itself.

Design constraints (issue #95):
- **Loopback-only by default.** The socket binds 127.0.0.1; binding anything
  else raises unless `allow_non_loopback=True` is passed explicitly from
  human-controlled configuration — never from agent input.
- **Deterministic.** All state comes from `seed()` with a fixed seed, so a
  reproduction is stable across runs.
- **Self-contained.** Stdlib http.server only; no network calls outward.
"""

from __future__ import annotations

import html
import json
import os
import sqlite3
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from evaluation.mock_target.fixtures import FIXTURES

DOCROOT = os.path.join(os.path.dirname(__file__), "docroot")


def seed_db(path: str) -> sqlite3.Connection:
    """Create the toy DB with deterministic seeded rows (SQLi/IDOR targets)."""
    conn = sqlite3.connect(path)
    conn.executescript(
        """
        DROP TABLE IF EXISTS users;
        CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, email TEXT);
        INSERT INTO users VALUES (1,'alice','alice@example.test');
        INSERT INTO users VALUES (2,'bob','bob@example.test');
        INSERT INTO users VALUES (3,'carol','carol@example.test');
        DROP TABLE IF EXISTS invoices;
        CREATE TABLE invoices (id INTEGER PRIMARY KEY, owner TEXT, amount INTEGER);
        INSERT INTO invoices VALUES (1001,'alice',42);
        INSERT INTO invoices VALUES (1002,'bob',7);
        INSERT INTO invoices VALUES (1003,'carol',999);
        """
    )
    conn.commit()
    return conn


def write_docroot() -> None:
    """Deterministic files the path-traversal fixture may legitimately serve."""
    os.makedirs(DOCROOT, exist_ok=True)
    with open(os.path.join(DOCROOT, "public.txt"), "w") as f:
        f.write("public fixture content\n")
    with open(os.path.join(DOCROOT, "secret.txt"), "w") as f:
        # Fake secret: fixtures must never carry real credentials.
        f.write("FAKE-secret-for-path-traversal-demo changeme\n")


class MockTargetHandler(BaseHTTPRequestHandler):
    server_version = "MockTarget/1.0"
    db_path: str = ":memory:"

    @property
    def db(self) -> sqlite3.Connection:
        # ThreadingHTTPServer serves each request on its own thread; sqlite
        # connections are thread-affine, so open one per request.
        conn = sqlite3.connect(self.db_path)
        self._db_conn = conn  # keep alive for the duration of the request
        return conn

    # -- helpers ---------------------------------------------------------
    def _send(self, status: int, body: str, content_type: str = "text/html; charset=utf-8"):
        data = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, fmt, *args):  # quiet by default; tests capture via access_log
        pass

    def do_GET(self):  # noqa: N802 (http.server API)
        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query)
        route = parsed.path

        if route == FIXTURES["reflected_xss"].path:
            q = qs.get("q", [""])[0]
            # VULN: reflected unescaped.
            return self._send(200, f"<html><body>Results for: {q}</body></html>")

        if route == "/comments":
            comments = getattr(self.server, "stored_comments", [])
            rendered = "".join(f"<p>{c}</p>" for c in comments)  # VULN: unescaped
            return self._send(200, f"<html><body>{rendered}</body></html>")

        if route == FIXTURES["sqli"].path:
            uid = qs.get("id", [""])[0]
            # VULN: string interpolation into SQL.
            row = self.db.execute(f"SELECT id, username FROM users WHERE id = {uid}").fetchall()
            return self._send(200, json.dumps({"rows": row}), "application/json")

        if route.startswith("/invoices/"):
            inv_id = route.rsplit("/", 1)[-1]
            row = self.db.execute(
                "SELECT id, owner, amount FROM invoices WHERE id = ?", (inv_id,)
            ).fetchone()
            # VULN: no ownership check (IDOR). Auth is deliberately absent so
            # any caller can read any invoice.
            if row is None:
                return self._send(404, "not found")
            return self._send(200, json.dumps({"invoice": row}), "application/json")

        if route == FIXTURES["ssrf_fetcher"].path:
            target = qs.get("url", [""])[0]
            # VULN: fetches whatever URL it is given. In the fixture world this
            # is used to demonstrate loopback SSRF against this same server.
            try:
                import urllib.request

                with urllib.request.urlopen(target, timeout=5) as resp:  # noqa: S310
                    snippet = resp.read(4096).decode(errors="replace")
                    return self._send(200, f"<pre>{html.escape(snippet)}</pre>")
            except Exception as exc:  # noqa: BLE001 - fixture reports errors to client
                return self._send(502, f"fetch failed: {html.escape(str(exc))}")

        if route == FIXTURES["path_traversal"].path:
            name = qs.get("name", [""])[0]
            # VULN: join without containment check.
            full = os.path.join(DOCROOT, name)
            try:
                with open(full) as f:
                    return self._send(200, f"<pre>{html.escape(f.read())}</pre>")
            except OSError as exc:
                return self._send(404, f"cannot read: {html.escape(str(exc))}")

        return self._send(404, "<html><body>unknown fixture</body></html>")

    def do_POST(self):  # noqa: N802
        parsed = urlparse(self.path)
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length).decode()

        if parsed.path == "/comments":
            comment = parse_qs(body).get("comment", [""])[0]
            # Stored XSS sink: appended verbatim, served unescaped above.
            self.server.stored_comments.append(comment)  # type: ignore[attr-defined]
            return self._send(201, "stored")

        return self._send(404, "unknown fixture")


class MockTargetServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, port: int = 0, allow_non_loopback: bool = False):
        host = "127.0.0.1" if not allow_non_loopback else "0.0.0.0"
        # Fail closed: non-loopback binding is an explicit opt-out for humans,
        # and we still refuse it loudly here so tests can never enable it.
        if allow_non_loopback:
            raise ValueError("non-loopback binding is disabled in the fixture server")
        write_docroot()
        import tempfile

        fd, self.db_path = tempfile.mkstemp(suffix=".sqlite")
        os.close(fd)
        seed_db(self.db_path).close()
        self.stored_comments: list[str] = []
        MockTargetHandler.db_path = self.db_path  # handlers read via class attr
        super().__init__((host, port), MockTargetHandler)


def start_server(port: int = 0) -> tuple[MockTargetServer, str]:
    """Start on a random free loopback port; returns (server, base_url)."""
    server = MockTargetServer(port=port)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    host, bound = server.server_address[:2]
    return server, f"http://{host}:{bound}"
