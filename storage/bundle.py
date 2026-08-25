"""Campaign backup / export / import (PLAN §12).

A campaign export is a tar archive with a manifest listing every artifact's
digest. On import, each member's digest is re-verified before anything is
written into the destination store, so a corrupted or tampered bundle is
rejected wholesale rather than silently ingested.
"""

from __future__ import annotations

import hashlib
import io
import json
import tarfile
from dataclasses import asdict
from pathlib import Path

from .artifacts import ArtifactStore, ChecksumMismatch, _digest_path, _validate_digest
from .naming import validate_rel_path

MANIFEST_NAME = "manifest.json"
BUNDLE_VERSION = 1


def export_campaign(
    store: ArtifactStore,
    digests: list[str],
    dest: str | Path,
    metadata: dict | None = None,
) -> Path:
    """Write a verified bundle containing the given artifacts.

    Every artifact is streamed through a hash check on the way out, so an
    already-corrupt store produces a failed export, not a bad bundle.
    """
    manifest = {
        "bundle_version": BUNDLE_VERSION,
        "metadata": metadata or {},
        "artifacts": {},
    }
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for digest in digests:
            _validate_digest(digest)
            path = _digest_path(store.root, digest)
            if not path.exists():
                raise FileNotFoundError(f"artifact {digest} missing from store")
            # Verify while adding: read in chunks, hash, then add from bytes.
            h = hashlib.sha256()
            data = path.read_bytes()
            h.update(data)
            if h.hexdigest() != digest:
                raise ChecksumMismatch(f"artifact {digest}: store content hash {h.hexdigest()}")
            rel = f"artifacts/{digest[:2]}/{digest}"
            info = tarfile.TarInfo(rel)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
            manifest["artifacts"][digest] = {"size": len(data)}
        mbytes = json.dumps(manifest, indent=2, sort_keys=True).encode()
        minfo = tarfile.TarInfo(MANIFEST_NAME)
        minfo.size = len(mbytes)
        tf.addfile(minfo, io.BytesIO(mbytes))
    out = Path(dest)
    out.write_bytes(buf.getvalue())
    return out


def import_campaign(bundle: str | Path, store: ArtifactStore) -> list[str]:
    """Import a bundle into *store*. Returns the imported digests.

    Fails atomically-ish by design: every member is checksum-verified
    against the manifest before insertion; any mismatch aborts before new
    artifacts are written (existing identical digests are harmless no-ops).
    """
    with tarfile.open(bundle, mode="r") as tf:
        names = tf.getnames()
        if MANIFEST_NAME not in names:
            raise ValueError("bundle missing manifest.json")
        manifest = json.load(tf.extractfile(MANIFEST_NAME))  # type: ignore[union-attr]
        if manifest.get("bundle_version") != BUNDLE_VERSION:
            raise ValueError(f"unsupported bundle version {manifest.get('bundle_version')!r}")
        expected: dict[str, dict] = manifest["artifacts"]

        staged: dict[str, bytes] = {}
        for member in tf.getmembers():
            if member.name == MANIFEST_NAME:
                continue
            data = tf.extractfile(member).read()  # type: ignore[union-attr]
            digest = hashlib.sha256(data).hexdigest()
            # Identity check: name must equal content digest (no trusting
            # archive paths), and it must be listed in the manifest.
            if f"artifacts/{digest[:2]}/{digest}" != member.name:
                raise ChecksumMismatch(f"member {member.name!r}: name != content digest")
            if digest not in expected:
                raise ValueError(f"artifact {digest} not in manifest")
            if member.size != expected[digest]["size"]:
                raise ChecksumMismatch(f"artifact {digest}: size mismatch vs manifest")
            staged[digest] = data
        missing = set(expected) - set(staged)
        if missing:
            raise FileNotFoundError(f"bundle missing artifacts: {sorted(missing)[:5]}")
        for d in staged:
            store.put_bytes(staged[d])
        return sorted(staged)


def bundle_metadata(bundle: str | Path) -> dict:
    """Read just the manifest metadata from a bundle without importing."""
    with tarfile.open(bundle, mode="r") as tf:
        manifest = json.load(tf.extractfile(MANIFEST_NAME))  # type: ignore[union-attr]
    return manifest.get("metadata", {})


def stored_artifact_dict(a) -> dict:
    """Helper for serializing StoredArtifact records."""
    return asdict(a)


__all__ = [
    "BUNDLE_VERSION",
    "MANIFEST_NAME",
    "ChecksumMismatch",
    "bundle_metadata",
    "export_campaign",
    "import_campaign",
    "stored_artifact_dict",
    "validate_rel_path",
]
