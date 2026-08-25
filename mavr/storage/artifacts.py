"""Artifact storage on the local filesystem.

Every artifact is addressed by its UUID — the on-disk filename is a
hash of the UUID, not the original user-provided name. Every read/write
goes through a path-traversal check.
"""
from __future__ import annotations

import os
import re
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from mavr.observability.logging import get_logger

log = get_logger(__name__)

# A canonical artifact id is a lowercase UUIDv4 string ("-" allowed).
_UUID_RE: Final[re.Pattern[str]] = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
# Filename tail: safe hex/ext
_SAFE_TAIL_RE: Final[re.Pattern[str]] = re.compile(r"^[0-9a-fA-F._-]{1,128}$")


class ArtifactError(ValueError):
    """Raised when an artifact path is rejected."""


@dataclass(frozen=True)
class ArtifactStore:
    root: Path

    def __post_init__(self) -> None:
        root = Path(os.fspath(self.root)).expanduser().resolve()
        if root.exists() and not root.is_dir():
            raise ArtifactError(f"artifact root {root} is not a directory")
        root.mkdir(parents=True, exist_ok=True)
        object.__setattr__(self, "root", root)

    # ---- path validation -------------------------------------------------

    def _resolve(self, artifact_id: str, suffix: str | None = None) -> Path:
        if not isinstance(artifact_id, str) or not _UUID_RE.match(artifact_id):
            raise ArtifactError("artifact id must be a lowercase UUIDv4 string")
        if suffix is not None:
            if not _SAFE_TAIL_RE.match(suffix):
                raise ArtifactError("artifact suffix contains invalid characters")
        filename = artifact_id if suffix is None else f"{artifact_id}{suffix}"
        target = (self.root / filename).resolve()
        try:
            target.relative_to(self.root)
        except ValueError as exc:
            raise ArtifactError(f"artifact path {target} escapes root") from exc
        if target.is_symlink():
            raise ArtifactError(f"artifact path {target} is a symlink")
        if target.exists() and not target.is_file():
            raise ArtifactError(f"artifact path {target} is not a regular file")
        return target

    # ---- public api ------------------------------------------------------

    def write(self, artifact_id: str, data: bytes, suffix: str | None = None) -> Path:
        target = self._resolve(artifact_id, suffix)
        if target.exists():
            raise ArtifactError(f"artifact {artifact_id} already exists")
        tmp = target.with_suffix(target.suffix + ".tmp")
        with open(tmp, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, target)
        log.info("artifact_written", artifact_id=artifact_id, bytes=len(data))
        return target

    def read(self, artifact_id: str, suffix: str | None = None) -> bytes:
        target = self._resolve(artifact_id, suffix)
        with open(target, "rb") as fh:
            return fh.read()

    def exists(self, artifact_id: str, suffix: str | None = None) -> bool:
        try:
            return self._resolve(artifact_id, suffix).exists()
        except ArtifactError:
            return False

    def remove(self, artifact_id: str, suffix: str | None = None) -> None:
        target = self._resolve(artifact_id, suffix)
        if target.exists():
            target.unlink()

    def free_bytes(self) -> int:
        usage = shutil.disk_usage(self.root)
        return usage.free

    def is_writable(self) -> tuple[bool, str]:
        probe = self.root / ".mavr_write_probe"
        try:
            probe.write_text("ok", encoding="utf-8")
            probe.unlink()
            return True, f"artifact dir writable: {self.root}"
        except OSError as exc:
            return False, f"artifact dir not writable ({self.root}): {exc}"
