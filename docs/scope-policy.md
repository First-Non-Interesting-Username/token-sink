# Scope policy authoring guide

A scope policy is a YAML or JSON document that authorizes MAVR to
operate against a specific set of targets, with a specific set of
actions, at a specific rate. The default scope policy is empty: no
target, no method, no action. **Nothing is allowed until a scope
policy is in place.**

This page covers the schema, the safety knobs, and the supported
target syntax.

## Schema

A scope policy has the following fields. The `id` and `campaign_id`
are filled in by MAVR; the rest are user-provided.

| Field | Type | Description |
|---|---|---|
| `allowed_targets` | list of strings | Hostname patterns the agents may talk to. |
| `allowed_methods` | list of strings | HTTP methods the agents may use. |
| `action_allowlist` | list of strings | Action classes the agents may perform. |
| `rate_limit_per_minute` | integer | Per-campaign request rate. |
| `active_testing` | bool | Whether active testing is permitted. |
| `explicit_unsafe_networking` | bool | Whether the private-network denylist may be bypassed. |
| `human_approved` | bool | Whether a human has approved the policy. |

A complete, conservative policy for a typical engagement:

```yaml
allowed_targets:
  - "staging.example.com"
  - "*.staging.example.com"
allowed_methods: [GET, HEAD]
action_allowlist: [read, enumeration]
rate_limit_per_minute: 30
active_testing: false
explicit_unsafe_networking: false
human_approved: false
```

## Target syntax

The `allowed_targets` list is a list of hostname patterns. Three
syntaxes are supported:

* **Exact match** — `"staging.example.com"` matches only that host.
* **Subdomain wildcard** — `"*.example.com"` matches
  `api.example.com` and `anything.example.com` but NOT
  `example.com` itself.
* **Glob** — any string containing `*` is treated as a glob. A
  pattern like `*example.com` matches any host ending in
  `example.com`; use this with care.

IP addresses may appear in the list, but they are subject to the
private-network denylist (see below). To target a public IP
directly, list it explicitly.

## Action classes

The `action_allowlist` is a list of action classes. The full set
is defined in `mavr.policy.engine.ActionClass`:

| Action | Description |
|---|---|
| `read` | Fetch a URL and read its content. |
| `write` | Submit a form or POST data. |
| `enumeration` | Walk the target's directory tree or sitemap. |
| `active_test` | Send crafted inputs to the target to probe for bugs. |
| `destructive_mutation` | **Always prohibited**, regardless of policy. |
| `credential_attack` | **Always prohibited**, regardless of policy. |
| `exfiltration` | **Always prohibited**, regardless of policy. |
| `denial_of_service` | **Always prohibited**, regardless of policy. |

The last four action classes are hard-coded denials. Listing them
in `action_allowlist` has no effect; MAVR will refuse any call
classified as one of them, even with `human_approved=True`.

## Active testing

Setting `active_testing: true` allows the agents to send crafted
inputs. MAVR will still quarantine the call unless `human_approved`
is also set. In other words:

```yaml
active_testing: true
human_approved: true
```

is the minimum policy that permits active testing. The CLI also
requires an unconsumed approval token (action `active_testing`),
which expires when the campaign ends.

## Explicit unsafe networking

The private-network denylist (loopback, RFC1918, link-local,
multicast, CGNAT, cloud metadata 169.254.169.254) is enforced
unless the policy sets **both** `explicit_unsafe_networking: true`
**and** `human_approved: true`. The denylist is checked at request
time using DNS resolution results, so DNS rebinding cannot bypass
it.

Use this knob only when you have a legitimate reason to target a
host in a private range — for example, an internal staging
environment that resolves to a 10.x address. Even with the
override, every request is recorded in the audit log and the SSRF
check is re-run before each request.

## Rate limit

`rate_limit_per_minute` is a per-campaign limit. Exceeding the
limit puts the call in `quarantine` (it is not silently dropped;
the agent sees the reason and can choose to back off). The
counter is the rolling count of outbound requests in the last
60 seconds.

## Quorum policy

The quorum policy controls how PoC reviews are folded. The
supported values are:

* `all_accept` — every reviewer must accept.
* `all_accept_or_3_of_4_no_blockers` (default) — all reviewers
  accept, or 3 of 4 accept and no reviewer marked the PoC as
  unsafe / invalid.

The quorum policy is set on the campaign, not the scope policy.
You can change it at any time; existing reviews are not
re-folded.

## Dispute review

A finding whose first-cycle review concluded `incorrect` (the
agent marked it as not a real bug) is moved to `disputed`. A
second reviewer must file a `dispute` review with the same
verdict for the finding to be eligible for tombstoning. The
audit log records both review events.

## Tombstoning

A finding is only tombstoned (permanently removed from the active
set) after:

1. a `deletion` approval token has been minted, and
2. both the original review and a dispute review concluded
   `incorrect`.

The audit row records the actor, the approval id, and the ids of
the two reviews. A tombstoned finding can still be read for
forensic purposes; it is never silently deleted.

## What's NOT in the scope policy

* Provider selection — that's a router / config concern.
* Agent budgets — those are per-campaign and per-agent.
* Retention — the artifact and audit retention windows are
  config-level, not per-scope.
