"""Append-only, tamper-evident audit log (PLAN.md §15).

Every control action (kill switch activation, pause/resume, cancellation,
quarantine, approval decisions) must be recorded here. Records are hash-chained:
each entry includes the SHA-256 of the previous serialized record, so any
retroactive edit or deletion breaks the chain and is detectable via verify().
"""

from __future__ import annotations

import hashlib
import json
import threading
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def _now() -> str:
    return datetime.now(UTC).isoformat()


class AuditLog:
    """Hash-chained append-only audit log persisted as JSON lines."""

    def __init__(self, path: str | Path):
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._prev_hash = self._load_last_hash()

    def _load_last_hash(self) -> str:
        if not self._path.exists():
            return "0" * 64
        last = "0" * 64
        with open(self._path, "rb") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                rec = json.loads(line)
                last = rec["record_hash"]
        return last

    def append(self, event_type: str, payload: dict[str, Any], actor: str = "") -> dict[str, Any]:
        """Append one audit record; returns the stored record."""
        with self._lock:
            record = {
                "id": str(uuid.uuid4()),
                "ts": _now(),
                "event_type": event_type,
                "actor": actor,
                "payload": payload,
                "prev_hash": self._prev_hash,
            }
            # Hash covers everything except the hash field itself.
            body = json.dumps(record, sort_keys=True, separators=(",", ":"))
            record["record_hash"] = hashlib.sha256(body.encode()).hexdigest()
            self._prev_hash = record["record_hash"]
            with open(self._path, "a", encoding="utf-8") as f:
                f.write(json.dumps(record, sort_keys=True) + "\n")
            return record

    def entries(self) -> list[dict[str, Any]]:
        if not self._path.exists():
            return []
        out = []
        with open(self._path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    out.append(json.loads(line))
        return out

    def verify(self) -> bool:
        """True if the hash chain is intact (no edits/deletions)."""
        prev = "0" * 64
        for rec in self.entries():
            expected_input = {k: v for k, v in rec.items() if k != "record_hash"}
            body = json.dumps(expected_input, sort_keys=True, separators=(",", ":"))
            if hashlib.sha256(body.encode()).hexdigest() != rec["record_hash"]:
                return False
            if rec["prev_hash"] != prev:
                return False
            prev = rec["record_hash"]
        return True
