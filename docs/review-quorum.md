# Review-quorum edge semantics (PLAN §10.5, issue #142)

Decision table implemented by `findings/quorum.py::evaluate_quorum`,
configurable via the `review` config section (§16).

## Decision table (four-agent PoC review)

| accepts | blocking objection | re-review cycles used | outcome |
|---|---|---|---|
| 4/4 | none | any | **advance** (`quorum_unanimous_accept`) |
| 4/4 | >=1 | any | **hold** by default (`unanimous_accept_but_blocking_objection`); advances only if `allow_unanimous_over_block: true` |
| 3 | none | any | **advance** (`quorum_majority_no_block`) |
| 3 | >=1 | any | **hold** — quorum met but a safety/validity block overrides (`quorum_met_but_blocking_objection`) |
| 2 | any | < cap | **hold** (`below_quorum_pending_evidence`) |
| 0/4 (all reject) | any | < `max_re_review_cycles` | **hold** for revert + new evidence cycle (`all_reject_revert_cycle_N_of_M`) |
| 0/4 (all reject) | any | = cap | **force_quarantine** (`all_reject_re_review_cap_exhausted`) |

Blocking is structural: only a review whose
`blocking_safety_or_validity_objection` flag is set AND that cites a field in
`blocking_fields` (default: `validity`, `safety`) blocks. Reviews citing no
field with the flag set are treated as blocking conservatively.

## Severity vs validity disagreement

Severity/impact conflicts between reviewers NEVER block advancement — they
attach to the finding as dissent (PLAN §10.5). Only the safety and validity
fields are blocking. Configure via `review.blocking_fields`.

## Re-review cap

After an all-reject verdict, reverting to post-first-review for more evidence
is allowed at most `max_re_review_cycles` times (default 2). When the cap is
exhausted the next all-reject panel forces quarantine instead of looping.
Counting lives with the caller (the lifecycle engine passes
`re_review_cycles_used`).

## Late-arriving dissent

Reviewers never mutate prior reviews. A changed verdict after advancement is
recorded via `findings/quorum.py::record_late_dissent`, which returns a new
`amendment` entry pointing at the original review index and carrying both the
old and new verdicts. Append-only history stays intact.

## Config example

```yaml
review:
  mode: independent_first      # or discussion_first
  quorum_accepts: 3
  blocking_fields: [validity, safety]
  max_re_review_cycles: 2
  allow_unanimous_over_block: false
```

Defaults are the safe posture: one safety/validity objection holds a finding
even against unanimous accept, and infinite revert loops are impossible.
