"""False-positive lifecycle, score/metric feedback, and recurrence linking
(issue #263, PLAN §10/§8.3/§14).

Closes the loop the issue describes:

- **Explicit FP classification.** A finding becomes ``false_positive`` only
  through :meth:`FindingLifecycle.classify_false_positive` — justification is
  REQUIRED (empty rationale raises), and consensus follows the repo's
  dual-confirmation rule: two DISTINCT reviewers must both conclude against
  the finding (the classifier plus one independent confirmer). A single
  reviewer's "incorrect" alone never labels an FP.
- **Score feedback (§8.3).** Every adjudicated FP feeds the
  ``false_positive_detection`` category of the score system via a raw
  Observation attributed to the discovering agent's model — so models that
  produce FPs get worse scores, not silent deletion.
- **Research metrics (§14).** Adjudications emit ``research``-family samples
  (false positives confirmed/disputed, FP rate inputs) into the shared
  MetricsStore.
- **Recurrent-FP pattern detection.** A newly discovered finding whose
  root-cause fingerprint matches an already-adjudicated FP is LINKED back to
  that adjudication (``recurrent_of``) instead of restarting the full review
  cycle — reuses dedup's conservative fingerprint so linkage is deterministic.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from findings.dedup import root_cause_fingerprint
from findings.lifecycle import LifecycleError

# Score-system category this feedback lands in (PLAN §8.3 list).
FP_SCORE_CATEGORY = "false_positive_detection"


@dataclass(frozen=True)
class RecurrentFPLink:
    """A new finding linked back to an earlier adjudicated FP."""

    finding_uuid: str
    adjudicated_fp_uuid: str
    reason: str


def find_recurrent_fp(
    candidate: dict[str, Any],
    adjudicated_fps: list[dict[str, Any]],
) -> RecurrentFPLink | None:
    """Link a candidate finding to an adjudicated FP with the same root cause.

    ``adjudicated_fps`` entries need ``finding_uuid`` plus the fingerprint
    input fields (affected_asset/category/location/root_cause). Matching is
    exact-fingerprint ONLY — deliberately conservative so a look-alike is
    reviewed fresh rather than wrongly suppressed (same posture as dedup).
    """
    cand_fp = root_cause_fingerprint(candidate)
    for fp in adjudicated_fps:
        if root_cause_fingerprint(fp) == cand_fp:
            return RecurrentFPLink(
                finding_uuid=str(candidate.get("finding_uuid", "")),
                adjudicated_fp_uuid=str(fp["finding_uuid"]),
                reason="root-cause fingerprint matches an adjudicated false positive",
            )
    return None


def record_fp_score_feedback(
    score_store: Any,
    provider: str,
    model: str,
    discovering_model_metadata: dict[str, Any],
    recorded_at: float,
) -> Any:
    """Record one FP observation against the discovering agent's model.

    Reads ``provider``/``model_id`` out of the finding's
    ``model_provider_metadata`` shape when available; callers may pass them
    explicitly instead. An FP counts as a FAILURE observation in the
    ``false_positive_detection`` category — the §8.3 score engine handles
    small-sample damping itself.
    """
    provider = provider or str(discovering_model_metadata.get("provider", ""))
    model = model or str(discovering_model_metadata.get("model_id", ""))
    if not provider or not model:
        raise LifecycleError("FP score feedback requires provider/model attribution")
    # Imported lazily to avoid a hard dependency cycle at module load.
    from evaluation.scores import Observation  # local import by design

    obs = Observation(
        provider=provider,
        model=model,
        category=FP_SCORE_CATEGORY,
        success=False,
        recorded_at=recorded_at,
    )
    return score_store.record(obs)


def record_fp_metrics(
    metrics_store: Any,
    campaign_id: str | None,
    outcome: str,
    ts: float,
) -> None:
    """Emit research-family metric samples for an FP adjudication (§14).

    ``outcome`` is ``confirmed_false_positive``, ``disputed_overruled``, or
    ``contested_escalated``. Two samples per event: a count and a rate input
    (value=1) so aggregate queries can derive the false-positive rate without
    storing ratios.
    """
    if outcome not in ("confirmed_false_positive", "disputed_overruled", "contested_escalated"):
        raise LifecycleError(f"unknown FP adjudication outcome {outcome!r}")
    metrics_store.record(
        family="research",
        name=f"findings_{outcome}",
        value=1.0,
        campaign_id=campaign_id,
        tags={"kind": "false_positive"},
        ts=ts,
    )
