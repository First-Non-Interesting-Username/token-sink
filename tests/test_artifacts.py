"""Artifact storage path-traversal tests."""
from __future__ import annotations

import os
import uuid

import pytest

from mavr.storage.artifacts import ArtifactError, ArtifactStore


def _uuid() -> str:
    return str(uuid.uuid4())


def test_write_and_read_round_trip(artifact_store: ArtifactStore) -> None:
    aid = _uuid()
    target = artifact_store.write(aid, b"hello world")
    assert target.exists()
    assert artifact_store.read(aid) == b"hello world"
    assert artifact_store.exists(aid)


def test_artifact_id_must_be_uuid(artifact_store: ArtifactStore) -> None:
    with pytest.raises(ArtifactError):
        artifact_store.write("../etc/passwd", b"x")
    with pytest.raises(ArtifactError):
        artifact_store.write("not-a-uuid", b"x")
    with pytest.raises(ArtifactError):
        artifact_store.write(_uuid().upper(), b"x")  # uppercase rejected


def test_path_traversal_via_dotdot_rejected(artifact_store: ArtifactStore) -> None:
    # Anything that contains ".." must be rejected at the id check, but also
    # at the suffix check.
    with pytest.raises(ArtifactError):
        artifact_store.write(_uuid(), b"x", suffix="/../../etc/passwd")
    with pytest.raises(ArtifactError):
        artifact_store.write(_uuid(), b"x", suffix="..secret")


def test_invalid_suffix_chars_rejected(artifact_store: ArtifactStore) -> None:
    with pytest.raises(ArtifactError):
        artifact_store.write(_uuid(), b"x", suffix="/etc/passwd")


def test_cannot_overwrite_existing(artifact_store: ArtifactStore) -> None:
    aid = _uuid()
    artifact_store.write(aid, b"one")
    with pytest.raises(ArtifactError):
        artifact_store.write(aid, b"two")


def test_remove_and_recreate(artifact_store: ArtifactStore) -> None:
    aid = _uuid()
    artifact_store.write(aid, b"x")
    artifact_store.remove(aid)
    assert not artifact_store.exists(aid)
    artifact_store.write(aid, b"y")
    assert artifact_store.read(aid) == b"y"


def test_symlink_escape_rejected(tmp_path) -> None:  # noqa: ANN001
    root = tmp_path / "artifacts"
    root.mkdir()
    outside = tmp_path / "outside.bin"
    outside.write_bytes(b"outside")
    # create a symlink inside root pointing outside
    target = root / "linked.bin"
    os.symlink(outside, target)
    store = ArtifactStore(root)
    aid = _uuid()
    # The on-disk filename doesn't match our id, so write won't be used to
    # *create* a symlink. But reading with that id would create that file
    # path; our resolver refuses it because it's a symlink.
    with pytest.raises(ArtifactError):
        store.read(aid, suffix=".bin")
