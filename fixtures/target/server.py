"""Local mock-target fixture server (issue #95, PLAN §10.4/§19.2/§19.3).

A deliberately vulnerable demo web application shipped with the repo so the
PoC agent can probe a *controlled local target* instead of anything live.
It is stdlib-only (no new dependencies), binds to loopback only by default,
and serves seeded deterministic data so reproductions are stable across runs.

Vulnerability classes exposed (each route documents its own boundary):

- reflected XSS        — GET /search?q=
- stored XSS           — POST /comments then GET /comments
- SQL injection        — GET /users?id=  (toy sqlite DB)
- IDOR                 — GET /invoices/<n> with no ownership check
- SSRF-able URL fetcher — GET /fetch?url=  (no scheme/private-IP checks)
- path traversal       — GET /files?name=

Every request is recorded as an evidence artifact (request/response pair) so
a finding can cite exact reproductions. Nothing here ever makes an outbound
network call of its own; /fetch performs whatever the *requester* points it
at, which is precisely the vulnerability under test.

Run directly::

    python -m fixtures.target.server --port 0   # prints chosen base URL

or from Python::

    from fixtures.target.server import FixtureServer
    server = FixtureServer()
    base_url = server.start()          # random free loopback port
    ...
    server.stop()
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

# ---------------------------------------------------------------------------
# Deterministic seed data
# ---------------------------------------------------------------------------

SEED_USERS = [
    {"id": 1, "username": "alice", "email": "alice@example.test", "role": "admin"},
    {"id": 2, "username": "bob", "email": "bob@example.test", "role": "user"},
    {"id": 3, "username": "carol", "email": "carol@example.test", "role": "user"},
]

SEED_INVOICES = [
    {"id": i, "owner": SEED_USERS[i % len(SEED_USERS)]["username"], "amount_cents": 1000 * i}
    for i in range(1, 6)
]

SEED_COMMENTS = ["First post!", "Nice site."]

# Files the /files endpoint is meant to serve (path traversal escapes this).
PUBLIC_FILES = {
    "readme.txt": "This is a public fixture file.\n",
    "notes.txt": "Internal notes: nothing sensitive here.\n",
}

# A fake secret placed OUTSIDE the public file root to demonstrate traversal.
_TRAVERSAL_SECRET = "FLAG{fixture-traversal-evidence}\n"

FIXTURE_HOST = "127.0.0.1"


class FixtureDB:
    """Tiny sqlite DB re-created per server instance with fixed seed rows."""

    def __init__(self) -> None:
        # in-memory: every run starts identical, satisfying determinism
        self.conn = sqlite3.connect(":memory:", check_same_thread=False)
        cur = self.conn.cursor()
        cur.execute(
            "CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, email TEXT, role TEXT)"
        )
        cur.execute("CREATE TABLE comments (id INTEGER PRIMARY KEY AUTOINCREMENT, body TEXT)")
        for u in SEED_USERS:
            cur.execute(
                "INSERT INTO users VALUES (?, ?, ?, ?)",
                (u["id"], u["username"], u["email"], u["role"]),
            )
        for c in SEED_COMMENTS:
            cur.execute("INSERT INTO comments (body) VALUES (?)", (c,))
        self.conn.commit()

    def user_by_id_raw(self, user_id: str) -> list[sqlite3.Row]:
        """Deliberately string-interpolated query — this IS the SQLi fixture."""
        cur = self.conn.cursor()
        return cur.execute(f"SELECT id, username, email FROM users WHERE id = {user_id}").fetchall()

    def add_comment(self, body: str) -> None:
        cur = self.conn.cursor()
        cur.execute("INSERT INTO comments (body) VALUES (?)", (body,))
        self.conn.commit()

    def comments(self) -> list[str]:
        cur = self.conn.cursor()
        return [r[0] for r in cur.execute("SELECT body FROM comments ORDER BY id").fetchall()]


class EvidenceLog:
    """Thread-safe record of request/response pairs for citation as evidence."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._entries: list[dict] = []

    def record(self, method: str, path: str, status: int) -> dict:
        entry = {"ts": time.time(), "method": method, "path": path, "status": status}
        with self._lock:
            self._entries.append(entry)
        return entry

    def entries(self) -> list[dict]:
        with self._lock:
            return list(self._entries)


class FixtureHandler(BaseHTTPRequestHandler):
    # Injected by the server factory below.
    db: FixtureDB
    evidence: EvidenceLog
    doc_root: Path

    def log_message(self, format, *args):  # noqa: A002 - http.server API name
        pass

    # -- helpers ----------------------------------------------------------
    def _send(self, code: int, body: str, content_type: str = "text/html; charset=utf-8") -> None:
        data = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _record(self, status: int) -> None:
        self.evidence.record(self.command, self.path, status)

    # -- routes -----------------------------------------------------------
    def do_GET(self) -> None:  # noqa: N802 (http.server API)
        parsed = urlparse(self.path)
        route = parsed.path
        qs = parse_qs(parsed.query)

        if route == "/":
            self._record(200)
            self._send(200, "<h1>fixture-target</h1><p>deliberately vulnerable demo app</p>")

        elif route == "/search":  # reflected XSS
            q = qs.get("q", [""])[0]
            self._record(200)
            # WHY unescaped: reflected XSS fixture — q is echoed verbatim.
            self._send(200, f"<h1>Results</h1><p>No results for {q}</p>")

        elif route == "/comments":  # stored XSS sink
            items = "".join(f"<li>{c}</li>" for c in self.db.comments())
            self._record(200)
            self._send(200, f"<h1>Comments</h1><ul>{items}</ul>")

        elif route == "/users":  # SQLi
            uid = qs.get("id", ["1"])[0]
            try:
                rows = self.db.user_by_id_raw(uid)
                self._record(200)
                body = "<br>".join(f"{r[0]}|{r[1]}|{r[2]}" for r in rows) or "no such user"
                self._send(200, f"<h1>User</h1><p>{body}</p>")
            except sqlite3.Error as exc:
                self._record(500)
                # Verbatim error text helps demonstrate blind/error-based SQLi.
                self._send(500, f"query failed: {exc}")

        elif route.startswith("/invoice/"):  # IDOR
            try:
                inv_id = int(route.rsplit("/", 1)[1])
            except ValueError:
                self._record(404)
                self._send(404, "not found")
                return
            inv = next((i for i in SEED_INVOICES if i["id"] == inv_id), None)
            self._record(200 if inv else 404)
            if inv is None:
                self._send(404, "not found")
            else:
                # WHY no auth check: IDOR fixture — any caller reads any invoice.
                self._send(200, f"<pre>{json.dumps(inv)}</pre>", "application/json")

        elif route == "/fetch":  # SSRF-able URL fetcher
            target = qs.get("url", [""])[0]
            self._do_fetch(target)

        elif route == "/files":  # path traversal
            name = qs.get("name", [""])[0]
            candidate = (self.doc_root / name).resolve()
            # The check that *should* exist is intentionally absent; we only
            # refuse names that resolve outside the root when they don't exist,
            # so traversal to the planted secret succeeds but random paths 404.
            if candidate.is_file() and str(candidate).startswith(str(self.doc_root)):
                self._record(200)
                self._send(200, candidate.read_text(encoding="utf-8"), "text/plain; charset=utf-8")
            elif name == "../secret.txt" or (candidate.is_file() and ".." in name):
                self._record(200)
                self._send(200, candidate.read_text(encoding="utf-8"), "text/plain; charset=utf-8")
            else:
                self._record(404)
                self._send(404, "not found", "text/plain")

        elif route == "/__evidence":
            # Fixture-only introspection endpoint for tests/eval harnesses.
            self._record(200)
            self._send(
                200,
                json.dumps(self.evidence.entries()),
                "application/json",
            )

        else:
            self._record(404)
            self._send(404, "not found")

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path != "/comments":
            self._record(404)
            self._send(404, "not found")
            return
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length).decode("utf-8", "replace")
        body = parse_qs(raw).get("body", [""])[0]
        if not body:
            self._record(400)
            self._send(400, "missing body")
            return
        self.db.add_comment(body)
        self._record(201)
        # Stored XSS fixture: stored verbatim, rendered unescaped at GET above.
        self._send(201, "comment stored", "text/plain")

    def _do_fetch(self, target: str) -> None:
        """SSRF fixture: fetches an arbitrary attacker-chosen URL."""
        import urllib.request

        if not target:
            self._record(400)
            self._send(400, "missing url param", "text/plain")
            return
        req = urllib.request.Request(target, headers={"User-Agent": "fixture-target/1.0"})
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                payload = resp.read(64 * 1024).decode("utf-8", "replace")
                self._record(resp.status)
                self._send(200, payload, "text/plain; charset=utf-8")
        except Exception as exc:  # noqa: BLE001 — surface any failure as evidence
            self._record(502)
            self._send(502, f"fetch failed: {exc}", "text/plain")


class FixtureServer:
    """Loopback-bound fixture HTTP server with deterministic seed data.

    Refuses non-loopback interfaces unless ``allow_non_loopback=True`` is set
    explicitly (never set it in shipped code/tests — escape hatch only).
    """

    def __init__(self, port: int = 0, allow_non_loopback: bool = False) -> None:
        if not allow_non_loopback:
            host = FIXTURE_HOST
        else:
            host = "0.0.0.0"
        self.db = FixtureDB()
        self.evidence = EvidenceLog()
        # Plant the traversal target outside the served doc root.
        import tempfile

        self._tmpdir = Path(tempfile.mkdtemp(prefix="fixture-target-"))
        (self._tmpdir / "public").mkdir()
        for fname, content in PUBLIC_FILES.items():
            (self._tmpdir / "public" / fname).write_text(content, encoding="utf-8")
        (self._tmpdir / "secret.txt").write_text(_TRAVERSAL_SECRET, encoding="utf-8")

        handler = type(
            "BoundHandler",
            (FixtureHandler,),
            {
                "db": self.db,
                "evidence": self.evidence,
                "doc_root": self._tmpdir / "public",
            },
        )
        self.httpd = ThreadingHTTPServer((host, port), handler)
        # Loopback enforcement: assert what we actually bound to.
        bound_host, bound_port = self.httpd.server_address[:2]
        if not allow_non_loopback and bound_host not in ("127.0.0.1", "::1"):
            self.httpd.server_close()
            raise RuntimeError(f"refusing non-loopback bind: {bound_host}")
        self.port = bound_port

    @property
    def base_url(self) -> str:
        return f"http://{FIXTURE_HOST}:{self.port}"

    def start(self) -> str:
        t = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        t.start()
        self._started = True
        return self.base_url

    def stop(self) -> None:
        # shutdown() blocks forever if serve_forever was never entered.
        if getattr(self, "_started", False):
            self.httpd.shutdown()
        self.httpd.server_close()

    def cleanup(self) -> None:
        import shutil

        shutil.rmtree(self._tmpdir, ignore_errors=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="local mock-target fixture server (loopback only)")
    parser.add_argument("--port", type=int, default=0, help="port to bind (0 = random free port)")
    args = parser.parse_args(argv)
    server = FixtureServer(port=args.port)
    url = server.start()
    print(f"fixture-target listening on {url}")  # machine-readable base URL
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        pass
    finally:
        server.stop()
        server.cleanup()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
