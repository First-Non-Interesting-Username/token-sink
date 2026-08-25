# Safety & Scope Authoring Guide

How to write campaign scope, what the policy engine blocks and why.
The enforcement model is simple: **safety lives in policy code, not in
prompts.** A model instruction to do something out-of-scope is treated the
same as any other blocked action.

Status: planning-stage documentation aligned with
[PLAN.md §2, §5, §9, §15](../PLAN.md).

## Campaign scope: required fields

Every campaign must define all of the following before it can start. Missing
or ambiguous scope is itself a defined state — agents refuse or pause; they
never guess around it (PLAN §5).

| Field | Purpose | Example |
|---|---|---|
| Authorization reference + program name | Provable permission for the work | `security.hackclub.com program rules v2026-06` |
| In-scope targets | Domains, URLs, repos, packages, APIs, apps | `api.example.com`, `gh/example/app` |
| Out-of-scope targets | **Explicitly listed**, not merely absent | `www.example.com`, `*.third-party.net` |
| Allowed HTTP methods & test classes | Constrains active testing techniques | read-only recon; no SQLi payloads on prod |
| Prohibited actions | Hard blocks regardless of context | DoS, destructive mutation, spam, credential attacks, data exfiltration |
| Rate limits & concurrency per target | Protect target availability | 10 req/min, 2 concurrent per host |
| Budgets | Total duration, token budget, tool budget | 48h, 2M tokens |
| Active-testing enabled flag | Separates recon from active phases | off until human review |
| Human approval requirements | Which actions need a person | PoC on live target, submission |
| Data handling / retention settings | Storage lifetime, redaction rules | 90d retention, redact PII |

### Good practice when writing scope

- Scope narrowly and enumerate exclusions. "Everything under *.example.com"
  plus an explicit list of excluded hosts beats a vague description.
- Prefer local fixtures over live-target PoCs; PLAN §10.4 requires preferring
  a mock/fixture whenever it demonstrates the issue adequately.
- Set rate limits below the most conservative limit in the program's rules.
- Keep active testing disabled through discovery/review phases.

## What the policy engine blocks

Every tool call is evaluated against the campaign **before execution**. A
failed check produces a blocked event with an actionable explanation. The
following are always enforced by the safety layer (PLAN §15, §19.3):

- **Out-of-scope access** — any network action toward a target not in scope,
  including redirects that leave scope.
- **Private-network SSRF** — fetches to loopback/private/link-local/metadata
  addresses (`127.0.0.0/8`, `10/8`, `172.16/12`, `192.168/16`,
  `169.254/16` incl. the cloud metadata service, `::1`, `fd00::/8`),
  DNS-rebinding-style redirect chains to private IPs, and unsafe URL schemes.
- **Destructive commands** — even when a model instructs them; shell
  execution is disabled by default and needs explicit policy approval.
- **Secret leakage** — API keys/tokens/passwords never enter prompts, logs,
  reports, exports, or git; persisted output runs through the redaction
  pipeline (auth headers, cookies, tokens, personal data).
- **Prompt injection** — content from fetched pages or target artifacts is
  untrusted input and can never override system policy or campaign scope.
- **Unapproved endpoints** — secrets/sensitive data are not routed to
  providers not approved for them; paid models are unreachable in free-only
  mode; over-quota or failing-health providers are skipped.
- **Gate bypass** — findings cannot reach final output without passing every
  review gate; deletion requires dual independent confirmation plus a
  tombstone/audit record; external submission requires explicit human
  approval every time.

## Epistemic labeling

Agents working with search/extraction results must label claims as one of
(PLAN §9): source fact, agent inference, unverified claim, or evidence
requiring active confirmation. Every final claim must be traceable to
evidence or explicitly labeled as analysis (PLAN §21).

## If something gets blocked

A block is normal operation, not a bug. The blocked event includes the reason
and the rule that fired. To legitimately change behavior:

1. Fix the campaign definition (scope, allowed methods, limits) via the
   approval-gated scope-change path.
2. Never weaken scope checks, approval gates, or policy blocks to make a test
   easier — this is also a hard rule for agents working in this repo
   (AGENTS.md).

## Safety tests as contract

The guardrails above are covered by the dedicated safety suite
(`tests/safety/`, [testing.md](testing.md)) which runs as a required CI gate:
out-of-scope URL blocked, private-network SSRF blocked, destructive commands
blocked, secrets absent from logs/reports/exports/errors, and prompt-injection
content cannot override policy. If you add a new enforcement rule, add its
bypass attempt to the suite in the same PR.
