"""Unit + safety tests for the prompt/response capture store (issue #117)."""

from __future__ import annotations

import pytest

from agents.capture import CaptureRequest, CaptureStore, PrivacyMode, RedactionError
from storage.sqlite import SQLiteStorage


@pytest.fixture()
def storage(tmp_path):
    s = SQLiteStorage(tmp_path / "db.sqlite", tmp_path / "artifacts")
    s.migrate()
    yield s
    s.close()


def _req(**kw) -> CaptureRequest:
    defaults = dict(
        agent_uuid="agent-1",
        task_uuid="task-1",
        campaign_uuid="camp-1",
        correlation_id="corr-42",
        provider="openrouter",
        model="test-model",
        prompt="Find the admin panel at https://ex.com",
        response="The admin panel is open.",
        tool_call_payload={"url": "https://ex.com/admin"},
        input_tokens=10,
        output_tokens=5,
        latency_ms=120.0,
    )
    defaults.update(kw)
    return CaptureRequest(**defaults)


# --- privacy mode enforcement ---


def test_full_mode_stores_prompt_and_response(storage):
    store = CaptureStore(storage, mode=PrivacyMode.FULL)
    cap_id = store.capture(_req())
    rec = store.get(cap_id)["data"]
    assert rec["prompt_ref"] == "Find the admin panel at https://ex.com"
    assert rec["response_ref"] == "The admin panel is open."
    assert rec["prompt_hash"] and rec["privacy_mode"] == "full"


def test_hashes_only_mode_stores_hashes_not_bodies(storage):
    store = CaptureStore(storage, mode=PrivacyMode.HASHES_ONLY)
    cap_id = store.capture(_req())
    rec = store.get(cap_id)["data"]
    assert "prompt_ref" not in rec
    assert len(rec["prompt_hash"]) == 64
    assert set(rec["tool_call"]["keys"]) == {"url"}


def test_disabled_mode_records_metadata_only(storage):
    store = CaptureStore(storage, mode=PrivacyMode.DISABLED)
    cap_id = store.capture(_req())
    rec = store.get(cap_id)["data"]
    blob = str(rec)
    assert "admin panel" not in blob  # no content anywhere in the record
    assert rec["prompt_hash"] is None and rec["response_hash"] is None


def test_campaign_override_downward_only(storage):
    # full -> disabled is allowed (stores less)
    assert PrivacyMode.downward(PrivacyMode.FULL, PrivacyMode.DISABLED) is PrivacyMode.DISABLED
    strict = CaptureStore(storage, mode=PrivacyMode.DISABLED)
    with pytest.raises(ValueError, match="MORE"):
        strict.capture(_req(), mode_override=PrivacyMode.FULL)


# --- redaction gate ---


def test_redactor_masks_sensitive_values_before_store(storage):
    def redactor(payload):
        if isinstance(payload, str):
            return payload.replace("sk-live-secret", "[REDACTED]")
        return payload

    store = CaptureStore(storage, mode=PrivacyMode.FULL, redactor=redactor)
    cap_id = store.capture(_req(prompt="my key is sk-live-secret-123"))
    rec = store.get(cap_id)["data"]
    assert "sk-live-secret" not in rec["prompt_ref"]
    assert "[REDACTED]" in rec["prompt_ref"]


def test_failed_redaction_blocks_the_write_never_stores_raw(storage):
    def bad_redactor(payload):
        raise RuntimeError("redaction pipeline down")

    store = CaptureStore(storage, mode=PrivacyMode.FULL, redactor=bad_redactor)
    with pytest.raises(RedactionError):
        store.capture(_req(prompt="raw secret content"))
    # Nothing was persisted.
    assert storage.list_records("capture") == []


# --- correlation IDs join across event stream / logs ---


def test_correlation_id_join(storage):
    store = CaptureStore(storage, mode=PrivacyMode.HASHES_ONLY)
    cap_id = store.capture(_req(correlation_id="corr-abc"))
    assert store.get(cap_id)["data"]["correlation_id"] == "corr-abc"


# --- retention purge ---


def test_expired_captures_purged_and_audit_recorded(storage, tmp_path):
    from policy.audit import AuditLog

    audit = AuditLog(tmp_path / "audit.jsonl")
    t = [1000.0]
    store = CaptureStore(
        storage,
        mode=PrivacyMode.FULL,
        audit_log=audit,
        default_retention_s=100,
        now=lambda: t[0],
    )
    store.capture(_req(correlation_id="old"))
    t[0] = 1200.0  # past retention
    purged = store.purge_expired()
    assert purged == 1
    types = [e["event_type"] for e in audit.entries()]
    assert "capture.purged" in types
    # Second purge run: nothing left to purge.
    assert store.purge_expired() == 0


def test_large_payload_offloaded_to_artifact_store(storage):
    big = "x" * 200_000
    store = CaptureStore(
        storage,
        mode=PrivacyMode.FULL,
        put_artifact=storage.put_artifact,
        artifact_threshold_bytes=64 * 1024,
    )
    cap_id = store.capture(_req(response=big))
    ref = store.get(cap_id)["data"]["response_ref"]
    assert ref["offloaded"] is True
    assert storage.get_artifact(ref["artifact_sha256"]).decode() == big


@pytest.mark.safety
def test_safety_disabled_mode_never_leaks_content_even_with_full_request(storage):
    """Guardrail: DISABLED must hold even when the caller passes secret-laden
    bodies — no prompt/response text or hashes may reach the record."""
    store = CaptureStore(storage, mode=PrivacyMode.DISABLED)
    cap_id = store.capture(_req(prompt="password=hunter2 token=abc123", response="secret result"))
    blob = repr(store.get(cap_id))
    for leak in ("hunter2", "abc123", "secret result"):
        assert leak not in blob
