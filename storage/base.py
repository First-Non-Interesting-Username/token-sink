"""Abstract storage interface (PLAN.md §12).

Agents depend on this interface only; engines (SQLite now, others later)
implement it. All mutating operations are atomic from the caller's point of
view — either the full change lands or nothing does.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class Storage(ABC):
    """Transactional metadata DB + artifact store abstraction."""

    # --- lifecycle ---
    @abstractmethod
    def close(self) -> None:
        """Flush and release resources."""

    @abstractmethod
    def migrate(self) -> int:
        """Apply pending migrations; return current schema version."""

    @property
    @abstractmethod
    def schema_version(self) -> int:
        """Currently applied schema version."""

    # --- records ---
    @abstractmethod
    def insert_record(
        self, kind: str, record_id: str, data: dict[str, Any], idempotency_key: str | None = None
    ) -> str:
        """Insert a record of `kind`. Unique on (kind, id) and on idempotency_key.

        Returns the stored record id. Raises RecordExistsError when the same
        idempotency_key was already used — callers treat that as success
        (idempotent task execution per PLAN §12).
        """

    @abstractmethod
    def get_record(self, kind: str, record_id: str) -> dict[str, Any] | None:
        """Fetch one record by kind+id, or None."""

    @abstractmethod
    def update_record(
        self, kind: str, record_id: str, expected_version: int, patch: dict[str, Any]
    ) -> dict[str, Any]:
        """Optimistic-concurrency update; raises ConflictError if the stored
        version != expected_version. Returns the new full record."""

    @abstractmethod
    def list_records(self, kind: str, limit: int = 100) -> list[dict[str, Any]]:
        """List records of a kind, newest first."""

    # --- atomic state transitions ---
    @abstractmethod
    def transition(
        self, kind: str, record_id: str, from_state: str | None, to_state: str, reason: str = ""
    ) -> None:
        """Atomically move a record's `state` field from->to and append to its
        transition history. Fails if current state != from_state (when given).
        Append-only history means no silent edits (PLAN §10/§12)."""

    # --- artifacts ---
    @abstractmethod
    def put_artifact(self, data: bytes, suggested_name: str = "artifact.bin") -> tuple[str, str]:
        """Store bytes; returns (sha256, relative path). Content-addressed:
        identity is the hash, never the filename (PLAN §12)."""

    @abstractmethod
    def get_artifact(self, sha256: str) -> bytes:
        """Retrieve bytes by hash. Raises ArtifactNotFoundError if missing or
        if the checksum no longer matches (detects corruption/tampering)."""


class StorageError(Exception):
    pass


class RecordExistsError(StorageError):
    pass


class ConflictError(StorageError):
    pass


class ArtifactNotFoundError(StorageError):
    pass
