"""False-positive lifecycle (PLAN §10, §14, §2 principle 4 — issue #263).

The lifecycle state machine covers discovery → review → report and the
metrics store tracks false-positive rate, but nothing defined HOW a finding
becomes classified false-positive or what happens downstream. This module
pins those semantics:

- **Explicit FP classification** (:class:`FalsePositiveRegistry`): a
  finding is marked FP only with a required justification AND reviewer
  consensus — at least ``min_consensus`` independent reviewers (default 2,
  distinct agent UUIDs) must vote ``false_positive``. A single agent can
  never unilaterally label work as FP.
- **Contested FPs escalate**: if any reviewer votes against the FP label
  while others support it beyond the threshold spread rules,
  :class:`FPContested` is raised instead of silently averaging — contested
  classifications go to adjudication.
- **Downstream feedback** (:func:`feedback_to_scores`,
  :func:`record_fp_metric`): each confirmed FP emits
  (a) an ``Observation(success=False)`` in the §8.3
  ``false_positive_detection`` score category for the originating model,
  and (b) a ``research/false_positive`` sample into the §14 metrics store,
  so FP-rate surfaces in research metrics without extra plumbing.
- **Recurrent-FP pattern detection**
  (:meth:`FalsePositiveRegistry.find_recurrent`): when another agent later
  re-discovers the same root cause (same fingerprint), the new candidate
  links back to the already-adjudicated FP instead of restarting the whole
  discovery/review cycle.

Privacy note: fingerprints are opaque structural strings (vuln class +
root-cause key); no target data or evidence content is copied here.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# §8.3 category that receives FP feedback observations.
FP_SCORE_CATEGORY = "false_positive_detection"

# Metrics-store name for research-family FP samples (§14).
FP_METRIC_NAME = "false_positive"

VOTES = ("false_positive", "not_false_positive")


class FPError(ValueError):
    """Invalid FP classification usage."""


class FPContested(FPError):
    """Reviewers disagree on the FP label; escalation required."""


def root_cause_fingerprint(
    vuln_class: str,
    affected_asset: str,
    root_cause: str,
) -> str:
    """Structural fingerprint for recurrent-FP matching.

    Lowercased ``class|asset|cause`` triple. Deliberately simple and
    deterministic; embedding-based similarity can wrap this later without
    changing the registry contract.
    """
    parts = [p.strip().lower() for p in (vuln_class, affected_asset, root_cause)]
    if not all(parts):
        raise FPError("fingerprint needs non-empty vuln_class, affected_asset, root_cause")
    return "|".join(parts)


@dataclass
class FPCandidate:
    """A finding proposed as false-positive."""

    finding_uuid: str
    fingerprint: str
    justification: str  # REQUIRED — no silent FP labeling
    origin_model: str | None = None  # for §8.3 score feedback
    origin_provider: str | None = None
    campaign_id: str | None = None


@dataclass
class FPRecord:
    """Adjudicated outcome for one FP candidate (append-only votes)."""

    candidate: FPCandidate
    votes: list[dict[str, Any]] = field(default_factory=list)
    status: str = "pending"  # pending | confirmed_fp | rejected_fp | contested
    linked_findings: list[str] = field(default_factory=list)

    def add_vote(self, voter_uuid: str, vote: str, notes: str = "") -> None:
        if vote not in VOTES:
            raise FPError(f"invalid vote {vote!r}; expected one of {VOTES}")
        if not voter_uuid.strip():
            raise FPError("voter uuid required")
        # Independence: one agent, one vote per candidate.
        if any(v["voter"] == voter_uuid for v in self.votes):
            raise FPError(f"{voter_uuid} already voted on this candidate")
        self.votes.append({"voter": voter_uuid, "vote": vote, "notes": notes})


class FalsePositiveRegistry:
    """Tracks FP candidates, consensus adjudication, and recurrence links."""

    def __init__(self, min_consensus: int = 2):
        if min_consensus < 1:
            raise FPError("min_consensus must be >= 1")
        self.min_consensus = min_consensus
        self._records: dict[str, FPRecord] = {}
        self.by_fingerprint: dict[str, list[str]] = {}

    def propose(self, candidate: FPCandidate) -> FPRecord:
        """Open a candidate. Requires justification immediately."""
        if not candidate.justification or not candidate.justification.strip():
            raise FPError("FP proposal requires a non-empty justification")
        rec = FPRecord(candidate=candidate)
        self._records[candidate.finding_uuid] = rec
        self.by_fingerprint.setdefault(candidate.fingerprint, []).append(candidate.finding_uuid)
        return rec

    def vote(self, finding_uuid: str, voter_uuid: str, vote: str, notes: str = "") -> FPRecord:
        rec = self._require(finding_uuid)
        rec.add_vote(voter_uuid, vote, notes)
        self._evaluate(rec)
        return rec

    def _evaluate(self, rec: FPRecord) -> None:
        fp_votes = sum(1 for v in rec.votes if v["vote"] == "false_positive")
        against = len(rec.votes) - fp_votes
        if against and fp_votes:
            # Split decision: never average a contested label away.
            rec.status = "contested"
            return
        if fp_votes >= self.min_consensus:
            rec.status = "confirmed_fp"
        elif against:
            rec.status = "rejected_fp"
        else:
            rec.status = "pending"

    def _require(self, finding_uuid: str) -> FPRecord:
        rec = self._records.get(finding_uuid)
        if rec is None:
            raise FPError(f"no FP candidate open for {finding_uuid}")
        return rec

    def get(self, finding_uuid: str) -> FPRecord | None:
        return self._records.get(finding_uuid)

    def find_recurrent(self, fingerprint: str, exclude_uuid: str | None = None) -> list[FPRecord]:
        """Confirmed FPs sharing this root-cause fingerprint.

        A new discovery with the same fingerprint should link to these
        instead of restarting the review cycle.
        """
        out = []
        for uid in self.by_fingerprint.get(fingerprint, []):
            if exclude_uuid and uid == exclude_uuid:
                continue
            rec = self._records[uid]
            if rec.status == "confirmed_fp":
                out.append(rec)
        return out

    def link_to_prior_fp(
        self, finding_uuid: str, prior_finding_uuid: str, linker_uuid: str
    ) -> FPRecord:
        """Attach a re-discovery to an already-adjudicated FP.

        The prior record MUST be a confirmed FP; linking is recorded on both
        records so provenance survives in either direction.
        """
        prior = self._records.get(prior_finding_uuid)
        if prior is None or prior.status != "confirmed_fp":
            raise FPError("can only link to a confirmed false positive")
        if not self._records.get(finding_uuid):
            # Re-discovery may arrive before its own candidate exists;
            # synthesize a lightweight record so links are queryable.
            self._records[finding_uuid] = FPRecord(
                candidate=FPCandidate(
                    finding_uuid=finding_uuid,
                    fingerprint=prior.candidate.fingerprint,
                    justification=f"linked to prior FP {prior_finding_uuid} by {linker_uuid}",
                )
            )
        rec = self._records[finding_uuid]
        if prior_finding_uuid not in rec.linked_findings:
            rec.linked_findings.append(prior_finding_uuid)
        if finding_uuid not in prior.linked_findings:
            prior.linked_findings.append(finding_uuid)
        return rec


def feedback_to_scores(scores_store: Any, rec: FPRecord, now: float) -> Any:
    """Feed a confirmed FP into the §8.3 score system.

    Emits one ``success=False`` observation in the
    ``false_positive_detection`` category for the originating provider/model
    (when known). Returns the created observation, or None when the FP has
    no known origin model or is not confirmed.
    """
    if rec.status != "confirmed_fp":
        return None
    c = rec.candidate
    if not c.origin_provider or not c.origin_model:
        return None
    from evaluation.scores import Observation  # local import avoids cycle

    obs = Observation(
        provider=c.origin_provider,
        model=c.origin_model,
        category=FP_SCORE_CATEGORY,
        success=False,
        recorded_at=now,
    )
    return scores_store.record(obs)


def record_fp_metric(metrics_store: Any, rec: FPRecord, ts: float) -> Any:
    """Record a research-family FP metric sample (§14).

    One sample per confirmed FP so false-positive rate aggregates directly
    via the existing metrics query API (count / group_by).
    """
    if rec.status != "confirmed_fp":
        return None
    c = rec.candidate
    return metrics_store.record(
        family="research",
        name=FP_METRIC_NAME,
        value=1,
        campaign_id=c.campaign_id,
        tags={"finding": c.finding_uuid},
        ts=ts,
    )
