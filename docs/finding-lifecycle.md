# Finding Lifecycle (PLAN §10)

Implementation: `findings/lifecycle.py` — a storage-agnostic state machine
over versioned finding records with an append-only transition history.

## Design decisions

- **Storage-agnostic core.** The state machine talks to a `RecordStore`
  interface (load/save/history). A future DB-backed store only has to persist
  versions + transitions atomically; none of the gate logic changes.
- **States.** The linear §10 pipeline plus `quarantined` and `deleted`
  (tombstone). `deleted` is terminal; nothing transitions out of it.
- **Append-only history.** Every operation — including lease acquisition,
  review recording, and quorum outcomes that don't change state — appends a
  `Transition` with a pre-transition content hash. Records are never edited
  in place; each save is a new version.
- **Leases.** First-cycle review requires claiming via
  `claim_for_review`; a second claim is rejected. Leases are cleared on any
  state transition.
- **Dual-confirmation deletion (§10.2).** An "incorrect" first-review holds
  the finding in `review_cycle_1`. Only an independent dispute reviewer also
  concluding against it moves it to `deleted` — and even then every prior
  version and history entry survives (tombstone semantics). If the dispute
  supports the finding, it advances with all dissent attached in
  `reviews`.
- **Four-agent PoC review (§10.5).** Reviews record whether the reviewer saw
  prior reviews (`saw_prior_reviews`), supporting both independent-first and
  discussion-first modes; mode enforcement belongs to campaign policy.
  Quorum: all four accept, or >=3 accept with no blocking safety/validity
  objection (`require_all_accept=True` tightens to unanimity). All-reject ->
  `quarantined` by default, or `revert_from_poc_review` back to
  `validated_or_disputed`. Mixed no-quorum -> no transition, event logged.
- **Final output (§10.6).** `finalize_report` only fires after final_review
  passed (state `vulnerabilities`). Submission to external programs stays a
  human-approved action outside this module by design.
- **False-positive lifecycle (issue #263).** A finding becomes
  `false_positive` only via `classify_false_positive`, which REQUIRES a
  written justification (empty/whitespace raises) and dual-confirmation
  consensus: an "incorrect" review conclusion must already exist and the
  confirming reviewer must be a distinct agent (`require_distinct_reviewer`).
  Reachable from `review_cycle_1` and `validated_or_disputed`. The state is
  terminal for the normal pipeline; `contest_false_positive` reopens it back
  to `validated_or_disputed` with the contest reason in history. Adjudicated
  FPs keep full record + audit trail — they are reference material, not
  deleted work.

## False-positive feedback loops (issue #263)

`findings/false_positive.py` closes the downstream loop:

- **Score feedback (§8.3).** `record_fp_score_feedback` records a FAILURE
  observation in the `false_positive_detection` score category attributed to
  the discovering agent's model, so FP-heavy models rank lower over time.
- **Research metrics (§14).** `record_fp_metrics` emits `research`-family
  samples into the shared MetricsStore; aggregate queries derive the
  false-positive rate from them.
- **Recurrence detection.** `find_recurrent_fp` links a newly discovered
  finding to an already-adjudicated FP when dedup's root-cause fingerprint
  matches exactly (conservative: look-alikes are reviewed fresh). Linked
  findings set `recurrent_of_uuid` instead of restarting the review cycle.

## Tests

`tests/test_lifecycle.py` covers: happy path, lease rules, illegal
transitions, tombstone deletion, dispute overrule with dissent, quorum
policies, blocking objections, quarantine/revert/release, append-only
history, and content-hash tamper detection.

Run with: `python -m pytest tests/test_lifecycle.py`

`tests/unit/test_false_positive_lifecycle.py` covers the issue #263 flows:
justification enforcement, consensus rules, contest/reopen, recurrence
linking, score feedback attribution, and metric emission.
