"""Prompt/response capture store with privacy settings (issue #117, PLAN §3.1).

Captures what agents send to and receive from model providers — prompts,
responses, tool-call payloads, token counts, latency, errors — keyed by
correlation IDs so captures join the event stream (#42) and logs (#135).

Design decisions (per AGENTS.md):

- Redaction-before-persist: the redactor (issue #29 pipeline, injectable)
  runs on every payload BEFORE anything is stored. A failed redaction check
  (redactor raises) blocks the write entirely — raw secrets are never at
  rest. Same fail-closed shape as observability/logs.py.
- Privacy modes per §16: ``full`` stores everything; ``hashes_only`` stores
  SHA-256 hashes of prompt/response instead of bodies (still enough to
  correlate/dedupe without keeping content); ``disabled`` records only
  metadata (counts, timing, error class) with no content at all. Campaigns
  may override the system mode DOWNWARD only (full → hashes_only/disabled);
  an attempt to go upward raises.
- Retention: expired captures are purged by ``purge_expired()`` and every
  purge is recorded in the audit log (#85 chain) rather than happening
  silently.
- Large payloads: bodies above ``artifact_threshold_bytes`` are offloaded to
  the artifact store (#46) via a pluggable ``put_artifact`` callable, and the
  capture keeps only the reference + hash.

Storage backend is injected (any object with insert/get/list record methods,
e.g. storage.base.Storage) — this module owns policy, not persistence.
"""

from __future__ import annotations

import enum
import hashlib
import time
from dataclasses import dataclass, field
from typing import Any

# Pluggable redaction function (issue #29 pipeline): takes a JSON-compatible
# object, returns it with sensitive values masked.
Redactor = Any


class PrivacyMode(enum.StrEnum):
    """Capture privacy levels (PLAN §16). Ordered from most to least content."""

    FULL = "full"
    HASHES_ONLY = "hashes_only"
    DISABLED = "disabled"

    @classmethod
    def downward(cls, system: PrivacyMode, requested: PrivacyMode) -> PrivacyMode:
        """Campaign override of the system mode, downward-only.

        A campaign may keep LESS than the system allows but never more:
        full→hashes_only/disabled ok; hashes_only→disabled ok; any upward
        step is refused rather than silently widened.
        """
        order = [cls.FULL, cls.HASHES_ONLY, cls.DISABLED]
        if order.index(requested) < order.index(system):
            raise ValueError(
                f"campaign requested privacy mode {requested.value!r} which stores MORE "
                f"than the system mode {system.value!r} — upward override is not allowed"
            )
        # The effective mode is the more restrictive of the two.
        return requested if order.index(requested) > order.index(system) else system


class RedactionError(Exception):
    """Raised when the redaction gate fails — the capture must not be stored."""


@dataclass(frozen=True)
class CaptureRequest:
    """One agent↔provider exchange to be captured."""

    agent_uuid: str
    task_uuid: str
    campaign_uuid: str
    correlation_id: str
    provider: str
    model: str
    prompt: str = ""
    response: str = ""
    tool_call_payload: dict[str, Any] = field(default_factory=dict)
    input_tokens: int | None = None
    output_tokens: int | None = None
    latency_ms: float | None = None
    error_class: str | None = None


class CaptureStore:
    """Privacy-gated capture pipeline (PLAN §3.1 component 6)."""

    def __init__(
        self,
        storage: Any,
        *,
        mode: PrivacyMode = PrivacyMode.FULL,
        redactor: Redactor | None = None,
        audit_log: Any = None,
        put_artifact: Any = None,
        artifact_threshold_bytes: int = 64 * 1024,
        default_retention_s: int = 30 * 24 * 3600,
        now: Any = time.time,
    ) -> None:
        self._storage = storage
        self.mode = mode
        self._redactor = redactor
        self._audit_log = audit_log
        self._put_artifact = put_artifact
        self.artifact_threshold_bytes = artifact_threshold_bytes
        self.default_retention_s = default_retention_s
        self._now = now

    # --- helpers ---
    @staticmethod
    def _sha256(data: str) -> str:
        return hashlib.sha256(data.encode("utf-8")).hexdigest()

    def _gate(self, payload: Any) -> Any:
        """Redaction-before-persist gate. Fail closed: a redactor crash blocks
        the write instead of storing un-redacted content."""
        if self._redactor is None:
            return payload
        try:
            return self._redactor(payload)
        except Exception as exc:  # noqa: BLE001 - fail closed on ANY redactor failure
            raise RedactionError(f"redaction gate failed; capture NOT stored: {exc}") from exc

    def _maybe_offload(self, body: str) -> dict[str, Any]:
        """Offload large bodies to the artifact store, keeping a reference."""
        size = len(body.encode("utf-8"))
        if self._put_artifact is not None and size > self.artifact_threshold_bytes:
            sha, path = self._put_artifact(body.encode("utf-8"))
            return {"offloaded": True, "artifact_sha256": sha, "artifact_path": path, "size": size}
        return {"offloaded": False}

    def capture(self, req: CaptureRequest, *, mode_override: PrivacyMode | None = None) -> str:
        """Capture one exchange under the effective privacy mode.

        Returns the stored capture id. Raises RedactionError when the
        redaction gate fails; ValueError on an illegal upward mode override.
        """
        effective = PrivacyMode.downward(self.mode, mode_override) if mode_override else self.mode
        now_s = self._now()
        retention_until = now_s + self.default_retention_s

        base: dict[str, Any] = {
            "schema_version": 1,
            "record_type": "capture",
            "agent_uuid": req.agent_uuid,
            "task_uuid": req.task_uuid,
            "campaign_uuid": req.campaign_uuid,
            "correlation_id": req.correlation_id,
            "provider": req.provider,
            "model": req.model,
            "privacy_mode": effective.value,
            "input_tokens": req.input_tokens,
            "output_tokens": req.output_tokens,
            "latency_ms": req.latency_ms,
            "error_class": req.error_class,
            "captured_at": now_s,
            "retention_until": retention_until,
        }

        if effective is PrivacyMode.DISABLED:
            # Metadata only — never any content or even its hash.
            base["prompt_hash"] = None
            base["response_hash"] = None
            base["tool_call"] = {"presented": bool(req.tool_call_payload)}
        elif effective is PrivacyMode.HASHES_ONLY:
            base["prompt_hash"] = self._sha256(req.prompt) if req.prompt else None
            base["response_hash"] = self._sha256(req.response) if req.response else None
            base["tool_call"] = {"keys": sorted(req.tool_call_payload.keys())}
        else:  # FULL
            # Redact first, then decide about offloading — the redacted text is
            # what gets hashed/offloaded/stored.
            prompt = self._gate(req.prompt)
            response = self._gate(req.response)
            tool_call = self._gate(req.tool_call_payload)
            base["prompt_hash"] = self._sha256(req.prompt) if req.prompt else None
            base["response_hash"] = self._sha256(req.response) if req.response else None
            po = self._maybe_offload(prompt)
            ro = self._maybe_offload(response)
            base["prompt_ref"] = po if po["offloaded"] else prompt
            base["response_ref"] = ro if ro["offloaded"] else response
            base["tool_call"] = tool_call

        cap_id = f"cap-{self._sha256(req.correlation_id + str(now_s))[:16]}"
        self._storage.insert_record("capture", cap_id, base)
        return cap_id

    def get(self, cap_id: str) -> dict[str, Any] | None:
        return self._storage.get_record("capture", cap_id)

    def purge_expired(self) -> int:
        """Delete captures past their retention point; record purges in the
        audit log (#52/#85) so deletion is itself auditable.

        The Storage interface has no delete_record — purge is modeled as a
        ``state`` transition to the terminal ``purged`` state (append-only
        history preserved, content no longer served)."""
        now_s = self._now()
        expired = []
        for r in self._storage.list_records("capture", limit=10_000):
            rec = r.get("data", r)
            if rec.get("retention_until", 0) <= now_s and r.get("state") != "purged":
                expired.append((r["id"], rec))
        count = 0
        for cap_id, rec in expired:
            self._storage.transition(
                "capture", cap_id, from_state=None, to_state="purged", reason="retention_expired"
            )
            count += 1
            if self._audit_log is not None:
                self._audit_log.append(
                    "capture.purged",
                    {"capture_id": cap_id, "correlation_id": rec.get("correlation_id")},
                    actor="capture_store",
                )
        return count
