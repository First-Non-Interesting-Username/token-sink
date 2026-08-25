# schemas/

Versioned JSON Schema (draft 2020-12) definitions for every core record type
required by PLAN.md §11. Each `<type>.schema.json` extends the shared envelope
in `common.schema.json` (`versioned_record`: UUID, schema_version,
created/updated timestamps, monotonic version + previous-version link).

## Conventions

- All records are **append-only**: changes create a new version with
  `previous_version_id` pointing at the prior one. No silent edits or deletes.
- Cross-schema references use relative `$ref` like
  `"common.schema.json#/$defs/uuid"` so validators can resolve them from this
  directory as the retrieval base.
- Timestamps are RFC 3339; identifiers are RFC 9562 UUIDs.
- `redaction_status` appears on any record that can carry sensitive content
  (PLAN §15). Auth fields store status only — never credential values.
- Epistemic labels (`source_fact`, `agent_inference`, `unverified_claim`,
  `requires_active_confirmation`) come from PLAN §9.

## Files

| Schema | PLAN section |
| --- | --- |
| common.schema.json | shared $defs |
| campaign.schema.json | §5 |
| scope_policy.schema.json | §5 |
| agent.schema.json | §6 |
| task.schema.json | §6/§7 |
| provider.schema.json | §8 |
| model.schema.json | §8.2–8.3 |
| router_decision.schema.json | §7 |
| search_result.schema.json | §9 |
| extracted_source.schema.json | §9 |
| evidence_item.schema.json | §10.1/§11 |
| finding.schema.json | §10/§11 |
| review.schema.json | §10.2/§10.5 |
| poc.schema.json | §10.4 |
| final_report.schema.json | §10.6 |
| usage_event.schema.json | §13.5/§14 |
| audit_event.schema.json | §14/§15 |

`tests/test_schemas.py` validates each schema against an example instance and
checks that invalid instances are rejected.
