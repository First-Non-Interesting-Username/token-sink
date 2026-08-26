# Finding version diffing (issue #119, PLAN §13.3/§10.6)

`findings/version_diff.py` produces structured diffs between two versions of
a finding record (versions come from `findings/lifecycle.py`'s RecordStore,
which persists every transition).

## Decisions

- **Structured diff, not text diff**: field-level `changed` entries
  (old/new), plus evidence-reference add/remove sets — the API (#32) and UI
  need semantics, not line noise.
- **Claim surface vs metadata**: changes to `CLAIM_FIELDS` (title,
  category, affected_asset, location, observation, hypothesis,
  repro_outline, suspected_impact, confidence) alter the technical claim;
  state/owner/redaction changes do not.
- **Claim-drift flag** (groundwork for #97): a claim-field change with NO
  evidence references at all on the newer version is flagged
  (`unlinked_claims` / `has_unlinked_drift`). Existing non-empty refs count
  as backing; per-claim attribution refinement lands with #97.
- **Redaction-aware rendering**: `render_markdown(..., redacted=True)`
  masks values but keeps structure, honoring the newer record's
  redaction_status.
- Pure read-only functions over records — no storage or network access.
