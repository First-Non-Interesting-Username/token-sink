# Record Schemas (PLAN §11)

Design notes for `schemas/`. Read alongside [PLAN.md §11](../PLAN.md).

## Why JSON Schema draft 2020-12

- The storage layer, API, and UI all consume the same records; one
  machine-readable contract prevents drift between them.
- 2020-12 is the current draft with `$defs`/`$ref` support in every mainstream
  validator (`jsonschema`, `check-jsonschema`, ajv).
- Markdown remains the human-readable report representation (PLAN §11);
  `final_report.schema.json` references the Markdown artifact rather than
  embedding it.

## Key design decisions

1. **Envelope fields on every record.** Each record carries `schema_version`
   (const per schema file — bump the const when the shape changes) and a
   `record_type` const matching its `$id`, so records are self-describing even
   when pulled out of the database or an export bundle.

2. **Identity is UUID-only.** Every cross-reference between records is a UUID
   (`$defs.uuid`), never a filename or title. This enforces the PLAN §12 rule
   that filenames alone never establish identity.

3. **Findings are versioned + append-only where it matters.**
   `finding.schema.json` carries `version`, `state`,
   `transition_reason`, and an append-only `transition_history` array.
   Consumers must append entries; validators should treat edits to history as
   corruption at the storage layer. Deletion is represented by the
   `tombstoned` state plus an audit event — never by removing rows (PLAN
   §10.2 dual-confirmation rule).

4. **Evidence classes are explicit.** `evidence_item.claim_type` implements
   PLAN §9's requirement to distinguish source facts, agent inference,
   unverified claims, and evidence requiring active confirmation.

5. **Reviews model dissent, not just verdicts.** `review.is_dissent` plus the
   finding's `dissent_summary` carry minority opinions forward when a finding
   advances (PLAN §10.2). `review.blind` supports both review modes
   (independent-first vs discussion-first).

6. **Secrets never enter schemas.** Provider credentials are referenced via
   `auth_ref` (a credential-store key), never embedded values. All content
   records carry `redaction_status`.

7. **Closed enums, `additionalProperties: false`.** Typos must fail validation
   loudly; new enum values require a deliberate `schema_version` bump. This is
   deliberately stricter than typical internal APIs because these records feed
   safety decisions (scope policy results, approval gates).

## Validation

- `scripts/validate_schemas.py` runs dependency-free structural checks (JSON
  parses, `$id`/`record_type` consistency, all `$ref`s resolve).
- When the project gains Python dependencies (Phase 1), add tests using the
  `jsonschema` package that validate example records for each type against its
  schema, including a full finding lifecycle example.

## Schema inventory

17 schemas covering every §11 record type: campaign, scope_policy, agent,
task, provider, model, router_decision, search_result, extracted_source,
evidence_item, finding, review, poc, final_report, usage_event, audit_event,
plus common definitions. See schemas/README.md for the table.
