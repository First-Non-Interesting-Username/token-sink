# Schemas

Versioned, machine-readable (JSON Schema draft 2020-12) definitions for every
core record type in PLAN.md §11. These schemas are the contract between the
storage layer, agents, API, and UI — the database and code must validate
against them, not the other way around.

## Conventions

- Every record has `schema_version` (integer, starts at 1) and `record_type`
  matching the schema's `$id` short name.
- Identity is always a UUIDv4 string (`"format": "uuid"`); filenames are never
  identity.
- Timestamps are RFC 3339 UTC strings (`"format": "date-time"`).
- Enums are closed; adding a value requires bumping `schema_version`.
- Additional properties are forbidden so typos fail validation instead of
  silently disappearing.

## Files

| Schema | Record |
|---|---|
| `common.schema.json` | Shared definitions ($defs): UUIDs, timestamps, hashes, provenance |
| `campaign.schema.json` | Campaign + embedded scope policy |
| `scope_policy.schema.json` | Scope policy (also usable standalone) |
| `agent.schema.json` | Agent/subagent identity, status, lease |
| `task.schema.json` | Task with dependencies, retries, budget |
| `provider.schema.json` | AI provider endpoint registration |
| `model.schema.json` | Model entry with capability scores |
| `router_decision.schema.json` | Router pool decision for a task |
| `search_result.schema.json` | Web search hit with provenance |
| `extracted_source.schema.json` | Extracted page content + cache metadata |
| `evidence_item.schema.json` | Immutable evidence artifact reference |
| `finding.schema.json` | Versioned finding record (the central type) |
| `review.schema.json` | Review vote incl. dissent (first review or PoC review) |
| `poc.schema.json` | Proof-of-concept reproduction |
| `final_report.schema.json` | Polished final report |
| `usage_event.schema.json` | Token/cost accounting event |
| `audit_event.schema.json` | Append-only audit trail event |

## Validation

`scripts/validate_schemas.py` is dependency-free: it checks that every schema
parses as JSON, declares `$schema`, `$id`, `schema_version` handling and
`record_type`, and that cross-references between schemas resolve. Once the
project gains dependencies, swap it for `check-jsonschema` / `jsonschema`
based tests (see docs/schemas.md).
