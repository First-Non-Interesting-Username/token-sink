# Severity rubric (PLAN §10.3)

Deterministic severity scoring so parallel agents and reviewers assign
consistent levels — issue #239.

Module: `findings/severity_rubric.py`

## Rubric

Five impact axes, each an integer 0–3 (missing/out-of-range values are
rejected, not defaulted — ambiguity must be explicit):

| Axis             | Meaning                                        | Weight |
|------------------|------------------------------------------------|--------|
| confidentiality  | data exposure                                  | 2.0    |
| integrity        | tampering / code execution                     | 2.0    |
| availability     | denial of service                              | 2.0    |
| reachability     | 0 unreachable … 3 remote unauthenticated       | 1.5    |
| preconditions    | inverted: 3 = no preconditions                 | 1.0    |

Weighted total (max 25.5) maps to inclusive bands:

| Total  | Severity |
|--------|----------|
| ≤0     | none     |
| ≤6     | low      |
| ≤12    | medium   |
| ≤19    | high     |
| >19    | critical |

`assess_severity(ImpactAssessment)` is pure and order-independent: the same
axes always yield the same level. Weights are module constants; do not
mutate at runtime.

## Severity changes

`apply_severity_change(...)` refuses no-op changes and empty rationales,
and returns a `SeverityChange` diff entry (before/after/stages/rationale)
that callers append to the finding's history — severity moves between
lifecycle stages are always justified and diff-visible.

## Reviewer disagreement

`evaluate_severity_panel(reviews, escalation_span=2)` takes each review's
`proposed_severity`. If proposals span ≥ `escalation_span` levels the
outcome is `escalate` — deliberately NOT averaged, since averaging
'low' + 'critical' into 'medium' launders disagreement into false
precision. Below threshold: unanimous → consensus, otherwise median.

## Fixtures

`tests/test_severity_rubric.py` carries ambiguous-impact fixtures
(hedged narratives like "may allow code execution") that resolve to one
consistent level once their axes are recorded.
