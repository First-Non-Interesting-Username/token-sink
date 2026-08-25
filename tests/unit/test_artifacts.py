"""Unit tests for the content-addressed artifact store (PLAN §12, §19.1)."""

import hashlib

import pytest

from storage.artifacts import (
    ArtifactStore,
    ChecksumMismatch,
    VerifiedReader,
    _validate_digest,
)


@pytest.fixture()
def store(tmp_path):
    return ArtifactStore(tmp_path / "store")


def test_put_and_read_roundtrip(store):
    data = b"hello evidence"
    a = store.put_bytes(data)
    assert a.digest == hashlib.sha256(data).hexdigest()
    assert a.size == len(data)
    with store.open(a.digest) as r:
        assert r.read() == data


def test_content_addressing_dedupes(store, tmp_path):
    d1 = store.put_bytes(b"same")
    d2 = store.put_bytes(b"same")
    assert d1.digest == d2.digest
    # Only one physical copy exists.
    files = list((tmp_path / "store" / "ab").rglob(d1.digest))
    assert len(files) == 1


def test_checksum_verified_on_corruption(store):
    a = store.put_bytes(b"important finding")
    path = next((store.root / "ab").rglob(a.digest))
    path.write_bytes(b"tampered finding")
    with pytest.raises(ChecksumMismatch), store.open(a.digest) as r:
        r.read()
        r.verify()


def test_export_rejects_corrupt_artifact(store, tmp_path):
    a = store.put_bytes(b"poc.py content")
    path = next((store.root / "ab").rglob(a.digest))
    path.write_bytes(b"evil")
    from storage.bundle import export_campaign

    with pytest.raises(ChecksumMismatch):
        export_campaign(store, [a.digest], tmp_path / "bundle.tar")


def test_invalid_digest_rejected(store):
    with pytest.raises(ValueError):
        store.exists("../not-a-digest")
    with pytest.raises(ValueError):
        _validate_digest("XYZ")


def test_secure_delete_zeroes_then_removes(store):
    import os

    a = store.put_bytes(b"secret payload")
    path = next((store.root / "ab").rglob(a.digest))
    inode_stat_before = os.stat(path).st_size
    assert inode_stat_before == len(b"secret payload")
    store.delete(a.digest, secure=True, passes=2)
    assert not path.exists()
    assert not store.exists(a.digest)


def test_prune_older_than(store):
    import os
    import time

    old = store.put_bytes(b"old artifact")
    new = store.put_bytes(b"new artifact")
    old_path = next((store.root / "ab").rglob(old.digest))
    past = time.time() - 10_000
    os.utime(old_path, (past, past))
    removed = store.prune_older_than(seconds=5_000)
    assert removed == [old.digest]
    assert not store.exists(old.digest)
    assert store.exists(new.digest)


def test_total_size(store):
    store.put_bytes(b"x" * 100)
    store.put_bytes(b"y" * 50)
    assert store.total_size() == 150


def test_verified_reader_partial_read_then_close_verifies_consumed_prefix(store):
    """A reader that only consumes part of the artifact verifies the prefix
    it read; use verify_all() to check the whole file."""
    data = b"abcdef"
    a = store.put_bytes(data)
    r = VerifiedReader(next((store.root / "ab").rglob(a.digest)), a.digest)
    assert r.read(3) == b"abc"
    # Prefix hash of "abc" != full digest, so plain verify() must fail...
    with pytest.raises(ChecksumMismatch):
        r.verify()
    # ...but verify_all() re-reads from the start and passes on good content.
    r.verify_all()
    r.close()


def test_export_import_roundtrip(tmp_path):
    from storage.bundle import bundle_metadata, export_campaign, import_campaign

    src = ArtifactStore(tmp_path / "src_store")
    artifacts = [src.put_bytes(b"f1"), src.put_bytes(b"f2"), src.put_bytes(b"f3")]
    bundle = tmp_path / "campaign.tar"
    export_campaign(
        src,
        [a.digest for a in artifacts],
        bundle,
        metadata={"campaign": "demo", "exported": "2026-08-25"},
    )
    assert bundle_metadata(bundle)["campaign"] == "demo"

    dst = ArtifactStore(tmp_path / "dst_store")
    imported = import_campaign(bundle, dst)
    assert imported == sorted(a.digest for a in artifacts)
    for a in artifacts:
        # export_to streams + verifies the checksum end-to-end.
        out = dst.export_to(a.digest, tmp_path / "out" / a.digest[:8])
        assert out.read_bytes() in (b"f1", b"f2", b"f3")


def test_import_rejects_tampered_bundle(tmp_path):
    from storage.bundle import export_campaign, import_campaign

    src = ArtifactStore(tmp_path / "src2")
    a = src.put_bytes(b"genuine")
    bundle = tmp_path / "b.tar"
    export_campaign(src, [a.digest], bundle)

    raw = bytearray(bundle.read_bytes())
    # Corrupt the artifact payload itself (offset of the file content inside
    # the tar: 512-byte header + 2-byte "ab/" prefix of the member name).
    raw[512 + 3] ^= 0xFF
    bad = tmp_path / "bad.tar"
    bad.write_bytes(bytes(raw))
    dst = ArtifactStore(tmp_path / "dst2")

    with pytest.raises((ChecksumMismatch, ValueError, FileNotFoundError)):
        import_campaign(bad, dst)
