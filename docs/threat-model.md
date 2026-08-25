# Threat model

This document describes the threat model MAVR is designed to
defend against, the specific adversary capabilities we assume,
and the residual risks that an operator must accept.

> **Authorized security testing only.** MAVR is a tool for
> conducting security testing against systems you are explicitly
> authorized to test. The threat model below is about defending
> MAVR itself — and the operator's host — from the targets it
> tests, from adversarial LLM providers, and from the contents of
> pages it fetches. It is **not** a license to point MAVR at
> systems you do not own.

## Adversary 1: malicious target

The target is the system MAVR is auditing. We assume the target
is hostile and may try to:

* trick the policy engine into letting MAVR reach private
  addresses (SSRF),
* serve HTML that contains prompt-injection payloads aimed at
  overriding the agent's instructions,
* include client-side JavaScript that exfiltrates the agent's
  data via request parameters,
* send the agent deliberately malformed responses to confuse the
  output validator,
* rate-limit or block the agent in order to degrade the audit.

### Defenses

* The scope policy engine maintains a hard-coded denylist of
  loopback, RFC1918, link-local, multicast, CGNAT, and
  cloud-metadata IP ranges, enforced at request time using DNS
  resolution.
* Fetched content is sanitized: HTML is parsed, dangerous tags
  and event handlers are stripped, and the result is wrapped in
  an `UNTRUSTED_INPUT` block before being passed to an LLM.
* The output schema is validated; malformed responses go to
  `quarantine_log` with the redacted input preserved.
* The `circuit_breaker` table prevents a single failing
  provider/model from monopolising the queue.

### Residual risk

* A target that is itself the host running MAVR (the "test the
  laptop" case) is only safe if the operator explicitly enables
  `explicit_unsafe_networking` and accepts the consequences.
* DNS rebinding between request-time resolution and the actual
  socket connect is mitigated by resolving at request time and
  re-checking before the connect; the small race window is
  documented as a residual risk in the safety guarantees page.

## Adversary 2: malicious LLM provider

We assume the LLM provider (or an upstream component the
provider depends on) may try to:

* return content that smuggles a prompt-injection payload,
* lie about the model's identity (e.g. a paid model masquerading
  as a free one),
* return malformed or oversized responses,
* reject traffic selectively to skew the routing decisions,
* exfiltrate data through a side channel (e.g. a uniquely-shaped
  request that encodes the prompt).

### Defenses

* The router pool refuses to dispatch to any model whose
  `free_status` is not `confirmed`. The free/paid classification
  is the responsibility of the model catalog, which is curated
  in-tree and verified out-of-band before each release.
* All provider responses are validated against the expected
  output schema. Malformed responses trigger a
  `ModelQualityError` and the task is quarantined.
* All output is wrapped as `UNTRUSTED_INPUT` before being used
  as input to the next agent. The runtime does not pass
  provider output back to the provider as a system message.
* Usage events record the actual `provider_id` and `model_key`
  used; the audit log makes any disagreement with the catalog
  visible.

### Residual risk

* A provider that returns a syntactically valid but
  semantically adversarial response (e.g. a polished report that
  subtly changes a claim) is caught by the four-agent review
  board in the common case. The probability of all four agents
  missing the same subtle change is non-zero; this is mitigated
  but not eliminated by the dispute review flow.
* Out-of-band verification of the model catalog is required
  before each release; the catalog itself is a trust root.

## Adversary 3: malicious operator

We assume the operator (or someone with shell access to the
host running MAVR) is the principal and is *not* an adversary.
This document is not a defense against a malicious operator —
if an attacker has shell access on your laptop, they can do
worse things than tamper with MAVR.

What the system does do is make the operator's actions
*auditable*: every state transition, every scope change, every
submission, and every tombstone is recorded in the audit log
with the actor and a reason. The audit log is append-only and
its integrity is verifiable via the per-bundle hash manifest.

## Adversary 4: malicious external content

A page MAVR fetches may contain content crafted to attack the
operator. The most realistic example is a page that returns a
malformed font, image, or PDF that exploits a vulnerability in
the host's image renderer or PDF viewer. MAVR fetches the raw
bytes but does not render images or PDFs in-process; rendering
is delegated to the operator when they open an artifact. The
mitigation is the same as for any browser-based workflow:
don't open artifacts from untrusted sources in a viewer that
auto-executes embedded content.

## What MAVR does not defend against

* A compromised host (kernel, libraries, etc.). MAVR assumes
  the Python interpreter and the operating system are honest.
* A compromised model provider that returns correct-looking but
  adversarial output that bypasses the four-agent review.
* Physical access to the host.
* Long-running exfiltration via timing side channels in the
  output channel. MAVR does not pad responses or randomize
  timings.
* Coercion of the operator.

## Safety properties

The following properties are *enforced by code* — they are
guarantees, not best-effort:

1. **No network call without scope.** Every outbound HTTP
   request goes through `mavr.policy.engine.ScopePolicyEngine`.
   The default policy allows nothing.
2. **No paid model without human approval.** The router pool
   refuses to dispatch to any model whose `free_status` is not
   `confirmed` unless the campaign has `human_approved=True`.
3. **No active test without human approval.** Active testing
   quarantines unless the scope policy sets
   `human_approved=True`.
4. **No submission without a human approval token.** The
   `submission` action requires an unconsumed token and an
   explicit `--human-approved` flag.
5. **No silent deletion.** Tombstoning requires a `deletion`
   approval token *and* a dual confirmation.
6. **No private network without explicit override.** The
   private-network denylist is enforced at request time and
   cannot be bypassed by configuration alone; it requires
   `explicit_unsafe_networking=True` and `human_approved=True`
   on the scope policy.
7. **No prompt-injection override of system policy.** Detected
   injection markers cause the affected content to be rejected
   at the door (description, PoC commands, polished body).
8. **No final output without traceability.** A finding only
   advances to `vulnerabilities` when every claim in the
   polished body either links to a real evidence UUID or is
   explicitly labeled as analysis.
9. **Kill switch stops new network actions.** The runtime
   refuses any handler that calls `charge_network()` while the
   kill switch is active. In-flight tasks are cancelled at the
   next safe point.
10. **All claims traceable.** Every factual claim in a final
    report must reference an `EvidenceItem` UUID or be labeled
    as analysis.

## How to verify the safety properties

The `tests/security/` directory contains tests that exercise
each property. The CI pipeline runs them on every PR. The
property tests are:

* `test_safety_guards.py` — properties 1, 2, 3, 4, 5, 6, 7, 9
* `test_recovery.py` — resumability and backup/restore
* `test_load.py` — load / scale
* `test_eval_fixtures.py` — known true / false / ambiguous
  findings and adversarial provider responses
* `test_acceptance.py` — the spec §21 acceptance tests,
  including property 8 (traceability) and the no-auto-submit
  invariant
