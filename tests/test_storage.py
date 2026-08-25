"""Unit tests for the storage layer (PLAN.md §12 requirements)."""

import hashlib

import pytest

from storage.base import (
    ArtifactNotFoundError,
    ConflictError,
    RecordExistsError,
    Storage,
)
from storage.sqlite import SQLiteStorage


@pytest.fixture()
def store(tmp_path):
    s = SQLiteStorage(tmp_path / "meta.db", tmp_path / "artifacts")
    s.migrate()
    yield s
    s.close()


def test_implements_interface(store):
    assert isinstance(store, Storage)


def test_migrations_versioned_and_idempotent(tmp_path):
    s = SQLiteStorage(tmp_path / "m.db", tmp_path / "a")
    assert s.schema_version == 0
    assert s.migrate() == 1
    assert s.schema_version == 1
    assert s.migrate() == 1  # re-running applies nothing, no error
    s.close()


def test_crash_recovery_reopens_cleanly(store, tmp_path):
    store.insert_record("task", "t1", {"objective": "x"})
    # Simulate restart: fresh instance over same files sees committed data.
    store.close()
    s2 = SQLiteStorage(tmp_path / "meta.db", tmp_path / "artifacts")
    s2.migrate()
    assert s2.get_record("task", "t1")["data"] == {"objective": "x"}
    s2.close()


def test_unique_record_ids(store):
    store.insert_record("agent", "a1", {"role": "reviewer"})
    with pytest.raises(RecordExistsError):
        store.insert_record("agent", "a1", {"role": "dup"})


def test_unique_event_ids_via_idempotency_key(store):
    store.insert_record("event", "e1", {}, idempotency_key="evt-abc")
    with pytest.raises(RecordExistsError):
        store.insert_record("event", "e2", {}, idempotency_key="evt-abc")


def test_optimistic_concurrency_update(store):
    store.insert_record("finding", "f1", {"title": "x"})
    rec = store.update_record("finding", "f1", expected_version=1, patch={"title": "y"})
    assert rec["data"]["title"] == "y"
    assert rec["version"] == 2
    with pytest.raises(ConflictError):
        store.update_record("finding", "f1", expected_version=1, patch={"title": "z"})


def test_atomic_transition_with_expected_state(store):
    store.insert_record(
        "finding",
        "f2",
        {},
    )
    store.transition("finding", "f2", None, "initial_findings")
    store.transition(
        "finding", "f2", "initial_findings", "review_cycle_1", reason="first review started"
    )
    assert store.get_record("finding", "f2")["state"] == "review_cycle_1"
    # Wrong expected state is rejected atomically — nothing changes.
    with pytest.raises(ConflictError):
        store.transition("finding", "f2", "validated_or_disputed", "impact_analysis")
    assert store.get_record("finding", "f2")["state"] == "review_cycle_1"


def test_transition_history_append_only(store):
    store.insert_record("finding", "f3", {})
    store.transition("finding", "f3", None, "initial_findings", reason="created")
    store.transition("finding", "f3", "initial_findings", "review_cycle_1")
    hist = store.get_transitions("finding", "f3")
    assert [(h["from_state"], h["to_state"]) for h in hist] == [
        (None, "initial_findings"),
        ("initial_findings", "review_cycle_1"),
    ]
    assert [h["seq"] for h in hist] == sorted(h["seq"] for h in hist)


def test_artifact_content_addressed_and_checksummed(store):
    data = b"evidence payload \x00\x01"
    sha, rel = store.put_artifact(data, suggested_name="poc.txt")
    assert sha == hashlib.sha256(data).hexdigest()
    # Identity is the hash; suggested_name never touches the stored path.
    assert rel == f"{sha[:2]}/{sha[2:4]}/{sha}"
    assert store.get_artifact(sha) == data
    sha2, _ = store.put_artifact(data)  # dedupe by content
    assert sha2 == sha


def test_artifact_corruption_detected(store):
    sha, rel = store.put_artifact(b"integrity matters")
    path = store.artifact_dir / rel
    path.write_bytes(b"tampered content!!")  # simulate disk corruption/tamper
    with pytest.raises(ArtifactNotFoundError, match="checksum mismatch"):
        store.get_artifact(sha)


def test_artifact_hash_must_be_wellformed(store):
    with pytest.raises(ArtifactNotFoundError):
        store.get_artifact("../../etc/passwd")


def test_invalid_record_ids_rejected(store):
    for bad in ("../escape", "", "has space", "x" * 300):
        with pytest.raises(ValueError):
            store.insert_record("thing", bad, {})


def test_export_all_roundtrip_shape(store):
    store.insert_record("campaign", "c1", {"name": "n"})
    store.put_artifact(b"blob")
    export = store.export_all()
    assert export["schema_version"] == 1
    assert export["tables"]["records"][0]["id"] == "c1"
    assert len(export["tables"]["artifacts"]) == 1
