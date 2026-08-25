
## Matcher semantics (#134)

`policy/matching.py` defines the canonical matching layer used by the engine
as an authoritative re-check after the legacy raw-string classification:

- **Canonicalization before comparison**: IDN → punycode (IDNA), lower-case,
  trailing root dot stripped, default ports (80/443) removed. Closes
  lookalike bypasses like `exämple.com`, `EXAMPLE.com.`, `example.com:443`.
- **Subdomain inclusion is opt-in** per rule (`include_subdomains`) with a
  real label boundary — `evilexample.com` can never match `example.com`.
  The engine currently derives rules with subdomain inclusion enabled to
  match the legacy matcher's behavior; rule-level opt-in exists for stricter
  campaign configs.
- **Path modes for URL rules**: `segment` (default) never lets `/api` match
  `/api-v2`; `prefix` does.
- **Out-of-scope always wins**, unlisted is default-deny.
- **Structured decisions**: every match returns rule ID, reason, and the
  request field evaluated; these surface in blocked-event explanations.
- The matcher is a pure function over (rule set, target) — reusable by CLI
  pre-flight checks and trivially fuzz-tested
  (`tests/unit/test_scope_matching.py` includes randomized-host property
  tests asserting no bypass form of an out-of-scope host matches in-scope).
