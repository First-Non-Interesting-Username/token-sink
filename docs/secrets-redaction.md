# Secrets handling and redaction (PLAN §15, issue #29)

## Where things live

- `src/tokensink/redaction.py` — the pattern-based redaction pipeline. Every
  piece of persisted output (logs, reports, exports, failed inputs/outputs
  kept for diagnosis) must pass through `redact()` before hitting disk.
  `RedactionResult.status` maps onto the `redaction_status` enum in
  `schemas/common.schema.json` (`pending_review` is set by callers when a
  record needs human eyes before it can be marked `no_sensitive_content_found`).
- `src/tokensink/credentials.py` — credential store interface + 0600 JSON-file
  backend. Callers reference credentials by *name* only; values never enter
  prompts, logs, or reports. A future OS-keyring backend implements the same
  three methods.
- `scripts/check_no_secrets.py` — CI gate (`.github/workflows/no-secrets.yml`)
  that fails when secret-shaped strings land in tracked files. Placeholder
  values (`sk-example-…`, `changeme`) are allowed on purpose: AGENTS.md
  encourages fake examples in docs.

## Conventions

- Redaction replacements keep a type hint: `[REDACTED:openai_key]`,
  `[REDACTED:authorization_header]`, … so redacted output stays diagnosable.
- Plain hex digests (content hashes) and UUIDs are deliberately NOT redacted —
  they carry provenance required by PLAN §9/§11, not secrets.
- Auth fields anywhere in the system record status only
  (`authenticated` / `unauthenticated`), never values.

## Testing

`tests/test_redaction.py` covers §19.1/§19.3 acceptance: provider key shapes,
auth/cookie headers, password key-value forms, PEM private keys, error-message
scrubbing, report-export mapping redaction, hash/UUID preservation, and file
store permissions (0600).
