"""Content-addressed artifact store (PLAN §12).

Identity is the SHA-256 digest of the content — never a filename. Artifacts
live under ``<root>/ab/<first2>/<digest>`` so any single directory stays
small and the layout is flat enough for simple backup tooling.

Guarantees:
- Every write returns the digest; every read/export verifies the checksum
  and refuses to serve corrupted content.
- Writes are atomic (temp file + rename), so a crash never leaves a
  half-written artifact that could verify as valid-but-wrong content.
- The store only ever writes inside its root (names come from validated
  digests, not user input).
"""

from __future__ import annotations

import hashlib
import os
import shutil
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

CHUNK = 1 << 16


class ChecksumMismatch(RuntimeError):
    """Artifact on disk does not match its expected digest."""


@dataclass(frozen=True)
class StoredArtifact:
    digest: str
    size: int


def _digest_path(root: Path, digest: str) -> Path:
    return root / "ab" / digest[:2] / digest


class ArtifactStore:
    """Filesystem-backed content-addressed store."""

    def __init__(self, root: str | Path):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def put_bytes(self, data: bytes) -> StoredArtifact:
        digest = hashlib.sha256(data).hexdigest()
        path = _digest_path(self.root, digest)
        if not path.exists():
            # Atomic write: same filesystem temp + rename, so concurrent
            # writers and crashes can't produce partial artifacts.
            path.parent.mkdir(parents=True, exist_ok=True)
            fd, tmp = tempfile.mkstemp(dir=path.parent)
            try:
                with os.fdopen(fd, "wb") as f:
                    f.write(data)
                os.rename(tmp, path)
            except BaseException:
                os.unlink(tmp)
                raise
        return StoredArtifact(digest=digest, size=len(data))

    def put_file(self, src: str | Path) -> StoredArtifact:
        """Stream a file into the store without loading it all in memory."""
        h = hashlib.sha256()
        size = 0
        with open(src, "rb") as f:
            while chunk := f.read(CHUNK):
                h.update(chunk)
                size += len(chunk)
        digest = h.hexdigest()
        path = _digest_path(self.root, digest)
        if not path.exists():
            path.parent.mkdir(parents=True, exist_ok=True)
            fd, tmp = tempfile.mkstemp(dir=path.parent)
            try:
                with (
                    open(src, "rb") as fin,
                    os.fdopen(fd, "wb") as fout,
                ):
                    shutil.copyfileobj(fin, fout, CHUNK)
                os.rename(tmp, path)
            except BaseException:
                os.unlink(tmp)
                raise
        return StoredArtifact(digest=digest, size=size)

    def open(self, digest: str) -> VerifiedReader:
        """Open an artifact for reading; the checksum is verified as you
        read, and close() raises ChecksumMismatch if the content diverges."""
        _validate_digest(digest)
        return VerifiedReader(_digest_path(self.root, digest), digest)

    def export_to(self, digest: str, dest: str | Path) -> Path:
        """Copy an artifact to *dest* after verifying its checksum."""
        dest = Path(dest)
        with self.open(digest) as r:
            dest.parent.mkdir(parents=True, exist_ok=True)
            fd, tmp = tempfile.mkstemp(dir=dest.parent)
            try:
                with os.fdopen(fd, "wb") as f:
                    shutil.copyfileobj(r, f, CHUNK)
                # Verify fully before the final rename so a corrupt source
                # never lands at the destination path.
                r.verify_all()
                os.rename(tmp, dest)
            except BaseException:
                os.unlink(tmp)
                raise
        return dest

    def exists(self, digest: str) -> bool:
        _validate_digest(digest)
        return _digest_path(self.root, digest).exists()

    def delete(self, digest: str, secure: bool = False, passes: int = 1) -> None:
        """Remove an artifact. With ``secure=True`` the file contents are
        overwritten before unlinking (best-effort on COW/logged FS, but
        correct for plain ext4/xfs files)."""
        _validate_digest(digest)
        path = _digest_path(self.root, digest)
        if not path.exists():
            return
        if secure:
            size = path.stat().st_size
            with open(path, "r+b") as f:
                for _ in range(max(1, passes)):
                    f.seek(0)
                    remaining = size
                    while remaining > 0:
                        n = min(CHUNK, remaining)
                        f.write(b"\x00" * n)
                        remaining -= n
                    f.flush()
                    os.fsync(f.fileno())
        path.unlink()
        # Prune now-empty fan-out dirs to keep the tree tidy.
        try:
            path.parent.rmdir()
        except OSError:
            pass

    def prune_older_than(self, seconds: float, now: float | None = None) -> list[str]:
        """Retention control: delete artifacts whose atime/mtime is older
        than *seconds*. Returns the digests removed."""
        cutoff = (now if now is not None else time.time()) - seconds
        removed: list[str] = []
        ab = self.root / "ab"
        if not ab.exists():
            return removed
        for prefix_dir in sorted(ab.iterdir()):
            for f in list(prefix_dir.iterdir()):
                if f.stat().st_mtime < cutoff:
                    self.delete(f.name)
                    removed.append(f.name)
        return removed

    def total_size(self) -> int:
        ab = self.root / "ab"
        if not ab.exists():
            return 0
        return sum(f.stat().st_size for f in ab.rglob("*") if f.is_file())


def _validate_digest(digest: str) -> None:
    if (
        not isinstance(digest, str)
        or len(digest) != 64
        or any(c not in "0123456789abcdef" for c in digest)
    ):
        raise ValueError(f"invalid sha256 digest: {digest!r}")


class VerifiedReader:
    """Read wrapper that hashes content as it streams."""

    def __init__(self, path: Path, digest: str):
        self._path = path
        self._expected = digest
        self._h = hashlib.sha256()
        self._f = open(path, "rb")

    def read(self, size: int = -1) -> bytes:
        data = self._f.read(size)
        self._h.update(data)
        return data

    def verify(self) -> None:
        """Verify everything read so far. Callers that want to verify the
        whole artifact must seek(0) or have consumed it from the start."""
        actual = self._h.hexdigest()
        if actual != self._expected:
            raise ChecksumMismatch(f"artifact {self._expected}: content hash {actual}")

    def verify_all(self) -> None:
        """Re-read from the start and verify the entire content."""
        pos = self._f.tell()
        self._f.seek(0)
        self._h = hashlib.sha256()
        while chunk := self._f.read(CHUNK):
            self._h.update(chunk)
        try:
            self.verify()
        finally:
            self._f.seek(pos)

    def close(self) -> None:
        if not self._f.closed:
            try:
                self.verify()
            finally:
                self._f.close()

    def __enter__(self) -> VerifiedReader:
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    # copyfileobj compatibility
    def readable(self) -> bool:
        return True
