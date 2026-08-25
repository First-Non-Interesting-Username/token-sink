"""Credential storage interface (PLAN §15, issue #29).

API keys live in the OS credential store where available; this module defines
the narrow interface other subsystems use, plus a file backend with 0600
permissions for environments without a keyring service. Credential *values*
never pass through logs or reports: only references (names) do.

The file backend stores a JSON mapping name -> secret at
``~/.config/token-sink/credentials.json`` with mode 0600. A future keyring
backend can implement the same three methods without touching callers.
"""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path


class CredentialStore:
    """Minimal interface: set / get / delete by reference name."""

    def set(self, name: str, secret: str) -> None:  # pragma: no cover - interface
        raise NotImplementedError

    def get(self, name: str) -> str | None:  # pragma: no cover - interface
        raise NotImplementedError

    def delete(self, name: str) -> bool:  # pragma: no cover - interface
        raise NotImplementedError


class FileCredentialStore(CredentialStore):
    """0600 JSON-file backend. Path is overridable for tests."""

    def __init__(self, path: Path | None = None) -> None:
        self.path = path or Path(
            os.environ.get("TOKEN_SINK_CREDENTIALS_PATH")
            or Path.home() / ".config" / "token-sink" / "credentials.json"
        )

    def _load(self) -> dict:
        if not self.path.exists():
            return {}
        return json.loads(self.path.read_text())

    def _save(self, data: dict) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # Write via a temp file then chmod before rename so the secret never
        # sits briefly in a world-readable file.
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data))
        tmp.chmod(stat.S_IRUSR | stat.S_IWUSR)  # 0600
        os.replace(tmp, self.path)
        self.path.chmod(stat.S_IRUSR | stat.S_IWUSR)

    def set(self, name: str, secret: str) -> None:
        data = self._load()
        data[name] = secret
        self._save(data)

    def get(self, name: str) -> str | None:
        return self._load().get(name)

    def delete(self, name: str) -> bool:
        data = self._load()
        if name not in data:
            return False
        del data[name]
        self._save(data)
        return True


def auth_status(store: CredentialStore, name: str) -> str:
    """Auth status WITHOUT exposing the value (PLAN §8.1/§15)."""
    return "authenticated" if store.get(name) is not None else "unauthenticated"
