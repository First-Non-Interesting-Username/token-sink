"""Tests for CLI launch/control of the local web UI (issue #306, PLAN §21)."""

from __future__ import annotations

import json
import socket
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from cli import webui


@pytest.fixture()
def state_dir(tmp_path: Path) -> Path:
    return tmp_path / "webui-state"


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class TestStateRoundTrip:
    def test_missing_state(self, state_dir):
        assert webui.read_state(state_dir) is None

    def test_round_trip(self, state_dir):
        webui.write_state(
            state_dir,
            webui.WebUiState(pid=123, port=4567, token="t", url="http://127.0.0.1:4567"),
        )
        st = webui.read_state(state_dir)
        assert st is not None and st.pid == 123 and st.port == 4567

    def test_corrupt_state_reads_as_none(self, state_dir):
        state_dir.mkdir()
        (state_dir / webui.STATE_FILE).write_text("{not json")
        assert webui.read_state(state_dir) is None


class TestProbe:
    def test_not_started(self, state_dir):
        kind, detail = webui.probe(None)
        assert kind == "stopped" and "not started" in detail

    def test_stale_pid(self, state_dir):
        stale = webui.WebUiState(pid=99999999, port=1, token="t", url="http://127.0.0.1:1")
        kind, _ = webui.probe(stale)
        assert kind == "stopped"

    def test_dead_http_alive_pid(self):
        # pid 1 is alive on Linux; port 1 answers nothing.
        alive = webui.WebUiState(pid=1, port=1, token="t", url="http://127.0.0.1:1")
        kind, detail = webui.probe(alive)
        assert kind == "stopped" and "not answering" in detail


class TestServerSecurity:
    def test_dashboard_get_and_hardened_post(self):
        from ui.server import create_server

        srv = create_server(token="secret-token")
        host, port = srv.server_address[:2]
        import threading

        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        try:
            base = f"http://{host}:{port}"
            with urllib.request.urlopen(base, timeout=2) as r:
                payload = json.loads(r.read())
            assert payload["status"] == "ok"

            # Mutating request without bearer token must fail closed (#152).
            req = urllib.request.Request(base + "/", method="POST", data=b"{}")
            try:
                urllib.request.urlopen(req, timeout=2)
                raised = False
            except urllib.error.HTTPError as e:
                raised = e.code == 401
            assert raised
        finally:
            srv.shutdown()
            srv.server_close()


class TestLifecycle:
    def test_start_status_stop_full_cycle(self, state_dir):
        state = webui.start(state_dir)  # picks a free port itself
        try:
            assert webui.http_ok(state.url)
            kind, detail = webui.status(state_dir)
            assert kind == "running", detail

            # double start refuses instead of spawning an orphan
            with pytest.raises(webui.WebUiError, match="already running"):
                webui.start(state_dir)

            result = webui.stop(state_dir)
            assert "terminated" in result
            kind, _ = webui.status(state_dir)
            assert kind == "stopped"
        finally:
            webui.stop(state_dir)

    def test_stop_when_never_started(self, state_dir):
        assert "not running" in webui.stop(state_dir)

    def test_start_on_busy_port_fails_closed(self, state_dir):
        blocker = socket.socket()
        blocker.bind(("127.0.0.1", 0))
        blocker.listen(1)
        busy = blocker.getsockname()[1]
        try:
            with pytest.raises(webui.WebUiError, match="cannot bind"):
                webui.start(state_dir, port=busy)
            # fail closed: no state file left behind
            assert webui.read_state(state_dir) is None
        finally:
            blocker.close()

    def test_cli_main_status_exit_code(self, state_dir):
        assert webui.main(["status", "--state-dir", str(state_dir)]) == 3
