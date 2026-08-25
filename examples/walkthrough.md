# Example walkthrough — dry-run from init to simulated finding lifecycle

This walkthrough uses **only** the files in `examples/` and the synthetic
fixtures in `evaluation/fixtures/`. Every target is an RFC 2606 reserved
domain (`example.com`) or a `local_fixture` entry.

> **Do not run anything in this guide against real targets.** The example
> campaign and scope policy exist so you can validate configuration offline.

## 0. Prerequisites

```bash
# Fake placeholder credential (AGENTS.md safety rule: never a real key).
export EXAMPLE_GATEWAY_API_KEY="sk-example-000000000000000000000000"
```

## 1. Init — copy the examples

```bash
cp examples/config.example.yaml tokensink.yaml
```

The campaign (`examples/campaign.example.json`) and scope policy
(`examples/scope-policy.example.json`) are records your operator tooling
loads; they share the campaign UUID
`00000000-0000-4000-8000-00000000c0de` so the policy references the
campaign it governs.

## 2. Config validation

The startup validator (`config/loader.py`, PLAN §16) parses and validates
the YAML, collecting all errors instead of failing on the first:

```bash
python -c "from config.loader import load_config; print(load_config('tokensink.yaml'))"
```

Expected: a populated config object with `scope_policy.active_testing_allowed = false`.

## 3. Schema validation of the example records (CI-enforced)

Every example record is validated against its JSON Schema by
`tests/unit/test_examples.py`, so the examples can never drift from the
schemas:

```bash
pytest tests/unit/test_examples.py -q
```

What the test proves:

- `campaign.example.json` satisfies every required field of
  `schemas/campaign.schema.json` (authorization reference, in/out-of-scope,
  prohibited actions, budgets, approval requirements, retention).
- `scope-policy.example.json` satisfies `schemas/scope_policy.schema.json`.
- Each `examples/providers/*.example.json` satisfies
  `schemas/provider.schema.json`, one per provider class (§8.1):
  native_free, gateway-with-filter, custom_endpoint.
- No example contains a literal credential value (`sk-example-...` strings
  appear only in this document and as env-var *names* elsewhere).
- All targets resolve to reserved/local-fixture identifiers only.

## 4. Mock provider test

Provider configs ship with `enabled: false`, so nothing can dispatch live
traffic until an operator explicitly enables them. To smoke-test a provider
without network access, point at the self-hosted class:

```bash
python - <<'EOF'
import json
p = json.load(open("examples/providers/custom-endpoint.example.json"))
print(p["provider_id"], p["kind"], p["base_url"], p["enabled"])
EOF
```

A real dry run against `http://127.0.0.1:8080/v1` would use your own local
model server; the example never assumes one is running.

## 5. Simulated finding lifecycle (fixtures from issue #47)

Drive the review pipeline over the §19.4 fixture set instead of live data:

```python
from evaluation.fixtures.loader import load_all

for fx in load_all():
    # A real run would create finding records (schemas/finding.schema.json),
    # route them through review (#50), and write final reports into
    # vulnerabilities/<finding-id>/ (#89). Here we just show the shape.
    print(fx["id"], fx["category"], fx["severity"])
```

Expected output includes `tp-001 true_positive high`,
`fp-001 false_positive ...`, plus ambiguous, conflicting-review, and
adversarial-response fixtures.

## 6. Where to go next

- `docs/operator-guide.md` — running campaigns safely.
- `docs/safety-and-scope.md` — authoring scope policies.
- `PLAN.md` §5/§16/§21 — the normative requirements behind these files.
