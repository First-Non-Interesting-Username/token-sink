# Multi-Agent Security Vulnerability Research System

## 1. Purpose

Build a Linux-only CLI application that launches a locally hosted web UI for coordinating multiple AI agents that discover, validate, document, and report security vulnerabilities for authorized submission to the Hack Club Security program:

- Target program: https://security.hackclub.com/
- Primary objective: produce accurate, reproducible, well-evidenced vulnerability reports.
- Operating principle: research only assets and behavior that are explicitly in scope and authorized.
- The system must favor correctness, safe testing, reproducibility, and human review over volume.

This document is an implementation plan for a coding LLM. It defines the product behavior, architecture, interfaces, state transitions, safety controls, observability requirements, and acceptance criteria. It does not implement the system.

---

## 2. Core Design Principles

1. **Scope before action**
   - Every campaign must have an explicit target scope, authorization source, allowed actions, prohibited actions, and rate limits.
   - Agents must refuse or pause when scope is missing or ambiguous.
   - Destructive, disruptive, credential-related, or out-of-scope actions must be blocked by policy, not merely discouraged in prompts.

2. **Parallelism by default**
   - Router decisions, independent reconnaissance tasks, reviews, and model calls should run concurrently where safe.
   - A slow or failed router must not stop the entire routing process.
   - Concurrency must still respect endpoint, target, campaign, and global rate limits.

3. **Evidence over assertions**
   - A finding is not reportable without evidence, reproduction steps, impact analysis, and an explicit confidence level.
   - Store raw observations separately from agent interpretations.
   - Preserve provenance for every claim.

4. **Redundancy for important decisions**
   - Use independent agents and reviewers for validation, false-positive handling, PoC review, and final report review.
   - Agents must not silently overwrite earlier conclusions.

5. **Human control**
   - Require user approval before active testing, PoC execution that could affect a target, submission, deletion of findings, or changes to scope.
   - Provide pause, resume, cancel, retry, and quarantine controls.

6. **Provider independence**
   - Model providers are plugins behind a common interface.
   - No provider should be required for the system to remain usable.
   - Provider failures should degrade gracefully and be visible in the UI.

---

## 3. High-Level Architecture

### 3.1 Components

1. **CLI application**
   - Creates and manages projects/campaigns.
   - Starts and stops the local web server and worker runtime.
   - Provides non-interactive commands for automation.
   - Displays startup diagnostics, configuration errors, and a local UI URL.

2. **Local web UI**
   - Shows active agents, queues, findings, costs/tokens, provider health, logs, and campaign state.
   - Provides approval and intervention controls.
   - Uses a local API and real-time event stream.

3. **Orchestrator**
   - Maintains campaigns, tasks, dependencies, retries, leases, locks, and lifecycle transitions.
   - Assigns UUIDs to agents and records all agent activity.

4. **Router pool**
   - Multiple independent router workers evaluate pending tasks in parallel.
   - Each router selects one or more suitable endpoints/models using capability scores, current load, rate limits, task requirements, and historical success.
   - A router failure must not block another router from making a decision.

5. **Endpoint registry and adapters**
   - Normalizes all supported AI providers behind one interface.
   - Supports free providers natively.
   - Supports partly free gateways only through an explicit free-model filter.
   - Supports user-defined custom endpoints.

6. **Agent runtime**
   - Executes role-specific agents and subagents.
   - Applies tool permissions, scope policy, timeouts, budgets, and output schemas.
   - Captures prompts, responses, tool calls, token counts, latency, and errors according to privacy settings.

7. **Search and extraction subsystem**
   - Uses `ddgs` for web search.
   - Uses `curl` and/or unauthenticated `jina.ai` for page extraction.
   - Caches results and records retrieval timestamps and URLs.
   - Must not treat search results as proof without source verification.

8. **Finding store**
   - Stores immutable evidence and versioned finding records.
   - Implements leases, ownership, review votes, transitions, and audit history.

9. **Policy and safety layer**
   - Validates target scope, allowed tools, request methods, rate limits, and approval requirements.
   - Enforces safe defaults independently from model instructions.

10. **Observability subsystem**
    - Emits structured events and metrics.
    - Powers dashboards, audit logs, diagnostics, and exportable run summaries.

---

## 4. Recommended Repository Structure

```text
project-root/
├── cli/
├── api/
├── ui/
├── orchestrator/
├── routers/
├── agents/
│   ├── roles/
│   ├── subagents/
│   └── prompts/
├── providers/
│   ├── adapters/
│   ├── registry/
│   └── model_catalog/
├── search/
├── policy/
├── findings/
├── storage/
├── observability/
├── schemas/
├── tests/
├── docs/
├── examples/
├── migrations/
├── config/
└── scripts/
```

Use clear module boundaries so providers, agent roles, storage engines, and UI components can be replaced independently.

---

## 5. Campaign and Scope Model

A campaign is the top-level unit of work. It must contain:

- Campaign UUID and human-readable name.
- Authorization reference and program name.
- In-scope domains, URLs, repositories, packages, APIs, or applications.
- Explicit out-of-scope targets.
- Allowed HTTP methods and test classes.
- Prohibited actions, such as denial of service, destructive mutation, spam, credential attacks, or data exfiltration.
- Maximum request rate and concurrency per target.
- Maximum total duration, token budget, and tool budget.
- Whether active testing is enabled.
- Human approval requirements.
- Data handling and retention settings.

The policy engine must evaluate every tool call against the campaign before execution. A failed policy check produces a blocked event and an actionable explanation.

---

## 6. Agent Identity and Runtime

Every agent and subagent receives:

- A globally unique UUID.
- Parent agent UUID, if applicable.
- Campaign UUID.
- Role and task UUID.
- Creation time, status, model/provider assignment, and budget.

Agents must be able to reference their own UUID and the UUIDs of relevant parent/child agents in their structured outputs.

### Agent statuses

```text
created → queued → assigned → running → waiting → completed
                              ├→ failed
                              ├→ cancelled
                              └→ blocked
```

The runtime must support:

- Heartbeats and stale-agent detection.
- Leases with expiration and safe reassignment.
- Per-agent token, request, time, and tool budgets.
- Cancellation propagation to subagents.
- Structured output validation.
- Retry policies that distinguish transient, permanent, policy, and model-quality failures.

### Subagents

Agents may create subagents for narrowly scoped tasks. A subagent request must specify:

- Parent UUID.
- Objective and expected output schema.
- Allowed tools and target scope.
- Budget and timeout.
- Whether active testing is allowed.
- Completion criteria.

The parent agent must summarize and cite subagent outputs rather than treating them as unquestioned truth.

---

## 7. Router Pool and Task Routing

### 7.1 Router behavior

The router receives a task description and selects suitable endpoint/model candidates. It must consider:

- Required capability: coding, search, reasoning, extraction, planning, report writing, review, or classification.
- Model capability scores.
- Historical success rate by task category.
- Current latency and error rate.
- Provider and model rate limits.
- Requests and tokens already sent in the current time windows.
- Remaining campaign and global budgets.
- Context-window and output-length requirements.
- Data sensitivity and endpoint trust level.
- Current queue depth and concurrency.
- Whether parallel calls or a sequential call is safer.

### 7.2 Parallel routers

- Run multiple routers independently.
- Each router returns a structured candidate plan with rationale, confidence, expected cost, and fallback options.
- A coordinator merges candidates using configurable policies:
  - consensus for high-risk tasks;
  - fastest eligible candidate for latency-sensitive tasks;
  - best score within budget for ordinary tasks;
  - diversity mode for independent reviews.
- Avoid routing all work to one model family when independent review is required.
- Router decisions must be reproducible from recorded inputs and model catalogs.

### 7.3 Routing safeguards

- Do not route to a paid model when the task is configured as free-only.
- Do not route to a provider that is over quota or failing health checks.
- Do not expose secrets or sensitive target data to endpoints that are not approved for it.
- Apply circuit breakers, backoff, and cooldowns.
- Maintain a dead-letter queue for tasks that cannot be safely routed.

---

## 8. Provider and Model Abstraction

### 8.1 Common provider interface

Each adapter should expose:

- Provider identity and API configuration.
- Authentication status without displaying secrets.
- Model discovery or a maintained model catalog.
- Model capabilities and context limits.
- Pricing/free status and free-tier constraints.
- Request and token rate limits.
- Streaming support.
- Tool-calling support.
- Structured-output support.
- Health check.
- Usage extraction.
- Error normalization.
- Cancellation and timeout support.

### 8.2 Provider classes

1. **Native free providers**
   - Supported directly through adapters.
   - Catalog only models currently eligible under the provider's free policy.

2. **Partly free gateways**
   - Include OpenCode Zen and Kilo Gateway.
   - Require a strict allowlist or metadata-based filter for free models.
   - Never assume a gateway model is free because the gateway itself is partly free.
   - If free-status metadata is unavailable, mark the model as unknown and exclude it from free-only routing until confirmed.

3. **Custom user endpoints**
   - Allow OpenAI-compatible and other explicitly supported APIs.
   - User must provide endpoint URL, model identifiers, capability metadata, free/paid classification, limits, and trust settings.
   - Validate connectivity without logging credentials.

### 8.3 Model score system

Maintain dynamic scores per model and task category, including at least:

- Latency.
- Coding.
- Search/retrieval synthesis.
- Reasoning.
- Security analysis.
- False-positive detection.
- Report writing.
- Structured-output reliability.
- Tool-use reliability.
- Cost/free-tier efficiency.

Each score should combine:

- Initial benchmark results.
- Ongoing success rate.
- Reviewer agreement.
- Task completion quality.
- Timeout and error rates.
- Confidence intervals and sample count.
- Recency weighting.

Do not let a small number of successful calls produce an overconfident score. Store raw observations and expose score confidence in the UI.

### 8.4 Benchmarking

Define a versioned benchmark suite containing representative, non-sensitive tasks for each category. Record:

- Benchmark version.
- Prompt and expected schema.
- Model/provider.
- Latency and token usage.
- Automated checks.
- Human or multi-agent evaluation.
- Pass/fail and quality score.

Benchmarks inform initial routing but must not replace live performance measurements.

---

## 9. Search and Website Extraction

### Search

- Use `ddgs` as the default search interface.
- Support query deduplication, result limits, safe-search configuration where available, and caching.
- Record query, timestamp, result URLs, snippets, ranking, and source status.
- Apply campaign scope filters to discovered URLs before follow-up actions.

### Extraction

- Use `curl` for direct retrieval where appropriate.
- Use unauthenticated `jina.ai` extraction as an optional fallback or alternate representation.
- Enforce timeouts, response-size limits, content-type checks, redirect policy, and SSRF protections.
- Do not fetch local, private, link-local, or metadata service addresses unless explicitly authorized and safely configured.
- Sanitize and label extracted content as untrusted input.
- Preserve raw content hashes and source URLs for provenance.

Search and extraction agents must distinguish:

- Source fact.
- Agent inference.
- Unverified claim.
- Evidence requiring active confirmation.

---

## 10. Finding Lifecycle

Use a state machine with versioned records and append-only transition history.

```text
initial_findings
  → review_cycle_1
  → validated_or_disputed
  → impact_analysis
  → poc_draft
  → poc_review
  → polished_report
  → final_review
  → vulnerabilities
```

### 10.1 Initial discovery

A discovery agent creates a finding containing:

- Finding UUID.
- Campaign UUID.
- Discovering agent UUID.
- Title and tentative category.
- Affected asset and exact location.
- Observation and initial hypothesis.
- Evidence references.
- Reproduction outline.
- Suspected impact.
- Confidence and uncertainty.
- Scope-policy result.
- Timestamp and tool provenance.

Store it in `initial_findings` or an equivalent state, not directly in the final vulnerabilities folder.

### 10.2 First review cycle

- A research agent claims the finding using a lease and its UUID.
- It investigates independently and records a conclusion: confirmed, likely, inconclusive, or incorrect.
- If incorrect, a separate reviewer evaluates the dispute.
- Delete only when both the original review and the independent dispute review conclude it is incorrect, and preserve a tombstone/audit record rather than silently removing history.
- If either reviewer supports the finding, advance it with all dissenting opinions attached.

### 10.3 Impact and root-cause analysis

A subsequent agent improves the technical picture:

- Root cause.
- Preconditions.
- Affected versions/components.
- Security boundary crossed.
- Attacker capabilities required.
- Confidentiality, integrity, and availability impact.
- Practical exploitability.
- Mitigations and suggested fix.
- Evidence gaps.

### 10.4 Proof of concept

A PoC agent creates the smallest safe, deterministic reproduction possible.

Requirements:

- Must be scoped to an approved target or a local fixture.
- Must avoid destructive actions and unnecessary data access.
- Must redact secrets and personal data.
- Must include setup, commands, expected output, cleanup, and safety notes.
- Prefer a local mock or fixture when it demonstrates the issue adequately.
- Require human approval before executing against a live target when configured by policy.

### 10.5 Four-agent PoC review

Run four independent reviewers, preferably with model/provider diversity. Each returns:

- Validity verdict.
- Reproduction quality.
- Scope and safety verdict.
- Severity/impact consistency.
- Missing evidence.
- Requested changes.
- Confidence.

The reviewers should be able to see prior review results only if the configured review mode allows discussion. Support two modes:

1. **Independent-first**: collect blind reviews, then allow discussion.
2. **Discussion-first**: reviewers can challenge and refine each other.

Advance only when the configured policy is satisfied. Default policy:

- All four must accept, or
- a quorum accepts and no reviewer identifies a blocking safety or validity issue.

If all four reject the finding, either quarantine it or revert it to the post-first-review state for additional evidence. Do not permanently delete it without the dual-confirmation deletion rule and audit trail.

### 10.6 Polishing and final review

- A polishing agent converts the validated finding into the final report format without changing technical facts.
- A final-review agent compares the polished report against source evidence, prior versions, and PoC output.
- Any altered claim must link to supporting evidence.
- The final report is written to `vulnerabilities/<finding-id>/` only after final review passes.
- Submission remains a separate, human-approved action.

---

## 11. Finding Data Schema

At minimum, define versioned schemas for:

- Campaign.
- Scope policy.
- Agent.
- Task.
- Provider.
- Model.
- Router decision.
- Search result.
- Extracted source.
- Evidence item.
- Finding.
- Review.
- PoC.
- Final report.
- Usage event.
- Audit event.

Every finding version should include:

- UUIDs for finding, campaign, agent, task, and parent finding.
- State and state-transition reason.
- Owner and lease information.
- Evidence references.
- Review votes and dissent.
- Model/provider metadata.
- Created/updated timestamps.
- Content hash.
- Redaction status.

Use JSON or another machine-readable format internally, with Markdown as a human-readable report representation.

---

## 12. Storage and Reliability

Provide a local-first storage layer with a transactional database for metadata and files for evidence/artifacts. The storage abstraction should allow a future replacement without changing agents.

Required features:

- Atomic state transitions.
- Idempotent task execution.
- Unique constraints for UUIDs and event IDs.
- Crash recovery.
- Resumable campaigns.
- Backup/export/import.
- Artifact checksums.
- Retention and secure deletion controls.
- Migration versioning.

Never use filenames alone as identity. Prevent path traversal and unsafe artifact names.

---

## 13. Web UI Requirements

### Main views

1. **Dashboard**
   - Active campaigns.
   - Agents running/waiting/blocked.
   - Tasks by state.
   - Findings by lifecycle stage.
   - Current alerts and approvals.

2. **Live activity**
   - Agent UUID, role, parent, current task, model/provider, elapsed time, status, and latest event.
   - Filters by campaign, role, provider, model, and status.

3. **Finding workspace**
   - Full lifecycle timeline.
   - Evidence and source provenance.
   - Review opinions and dissent.
   - Version diff.
   - PoC and safety status.
   - Claim-to-evidence traceability.

4. **Provider and model page**
   - Health, latency, errors, quotas, free/paid classification, score by category, confidence, and current load.

5. **Usage and costs**
   - Total requests and tokens.
   - Breakdown by provider, model, campaign, agent, task, and time range.
   - Input/output/cache tokens when available.
   - Estimated cost, with free-tier usage clearly separated from paid usage.

6. **Policy and approvals**
   - Pending approvals.
   - Blocked actions.
   - Scope configuration.
   - Active-testing status.
   - Audit history.

7. **Logs and diagnostics**
   - Structured logs with correlation IDs.
   - Error details safe for display.
   - Exportable run bundle.

### Real-time transport

Use a local event stream such as WebSocket or Server-Sent Events. The UI must recover after reconnecting by requesting events after the last known event ID.

---

## 14. Observability and Metrics

Track at least:

### Agent metrics

- Number active by role and campaign.
- Queue wait time.
- Runtime.
- Success/failure/cancellation rate.
- Subagents spawned.
- Retry count.
- Tool calls and blocked tool calls.

### Model/provider metrics

- Requests.
- Input/output/total tokens.
- Latency percentiles.
- Timeouts.
- Rate-limit responses.
- Other errors.
- Current and historical quota usage.
- Free versus paid calls.
- Score and confidence by category.

### Research metrics

- Findings discovered.
- Findings confirmed, disputed, reverted, quarantined, and deleted with dual review.
- False-positive rate.
- Review agreement.
- PoC acceptance rate.
- Time from discovery to final report.
- Evidence completeness.
- Reports requiring human edits.

### System metrics

- CPU, memory, disk usage, database size, queue depth, event lag, and UI/API health.

Metrics must be queryable by campaign and time range. Make privacy-preserving telemetry the default; do not send target data to external analytics services without explicit consent.

---

## 15. Security and Safety Requirements

- Store API keys in the OS credential store or protected local configuration; never put secrets in prompts, logs, reports, or git.
- Redact authorization headers, cookies, tokens, passwords, and personal data from all persisted output.
- Treat all web content, repository content, and model output as untrusted input.
- Defend against prompt injection in fetched pages and target artifacts.
- Use allowlists for network destinations and restrict unsafe URL schemes.
- Add SSRF, path traversal, command injection, and shell-escape protections.
- Run active tools with least privilege, isolated working directories, timeouts, and resource limits.
- Make shell execution disabled by default and require explicit policy approval.
- Separate read-only reconnaissance from active testing permissions.
- Add a kill switch that cancels all active tasks and prevents new network actions.
- Keep a tamper-evident audit log for approvals, blocked actions, state changes, and submissions.
- Make external submission a distinct final action requiring explicit human confirmation.

---

## 16. Configuration

Support a documented YAML or TOML configuration with sections for:

- Server host and port.
- Database and artifact paths.
- Provider credentials references.
- Provider/model allowlists.
- Free-only mode.
- Router count and concurrency.
- Agent budgets and timeouts.
- Search/extraction settings.
- Campaign defaults.
- Scope and active-testing policy.
- Review quorum.
- Retention and redaction.
- Logging and telemetry.

Validate configuration at startup and report all errors before launching workers.

---

## 17. CLI Surface

Define commands similar to:

```text
system init
system doctor
system serve
system campaign create
system campaign list
system campaign start <id>
system campaign pause <id>
system campaign stop <id>
system campaign export <id>
system provider list
system provider test <id>
system model benchmark
system finding list
system finding inspect <id>
system finding approve <id>
system finding reject <id>
system report export <id>
system logs
```

The exact names may change, but every UI action that changes state should have a safe, auditable CLI equivalent where practical.

---

## 18. Failure Handling

Define explicit behavior for:

- Provider outage.
- Provider quota exhaustion.
- Unknown free/paid model status.
- Router disagreement.
- Agent timeout.
- Stale lease.
- Malformed model output.
- Search or extraction failure.
- Scope-policy rejection.
- Database interruption.
- UI disconnect.
- Conflicting finding edits.
- PoC safety failure.

Use retries only for classified transient failures. Preserve failed inputs and outputs for diagnosis, with secrets and sensitive data redacted.

---

## 19. Testing and Evaluation Plan

The implementation should include:

1. **Unit tests**
   - State transitions.
   - Lease handling.
   - Scope checks.
   - Free-model filtering.
   - Token and request accounting.
   - Redaction.
   - URL and artifact validation.

2. **Integration tests**
   - Provider adapters against mocks.
   - Router pool failover.
   - Search/extraction caching.
   - Database recovery.
   - Event stream reconnection.
   - Finding lifecycle from discovery to final report.

3. **Safety tests**
   - Out-of-scope URL blocked.
   - Private-network SSRF blocked.
   - Destructive command blocked.
   - Secret removed from logs and reports.
   - Prompt-injection content cannot override system policy.

4. **Evaluation fixtures**
   - Known true positives.
   - Known false positives.
   - Ambiguous findings.
   - Conflicting reviewer opinions.
   - Malformed and adversarial provider responses.

5. **Load tests**
   - Many parallel routers.
   - Many agents and subagents.
   - Rate-limit pressure.
   - Large evidence collections.
   - UI event throughput.

6. **Acceptance tests**
   - A campaign can resume after restart.
   - Usage is accurately attributed by provider/model/agent/task.
   - No finding reaches final output without required review gates.
   - Every final claim can be traced to evidence or is explicitly labeled as analysis.

---

## 20. Delivery Phases

### Phase 1: Foundation

- Project layout.
- Configuration and secrets handling.
- Database and schemas.
- Campaign and scope policy.
- Agent UUIDs.
- Basic CLI and local API.

### Phase 2: Runtime and lifecycle

- Task queue.
- Agent runtime.
- Leases and retries.
- Finding state machine.
- Audit events.
- Basic Markdown artifacts.

### Phase 3: Providers and routing

- Common provider interface.
- Initial free-provider adapters.
- OpenCode Zen and Kilo Gateway free-model filtering.
- Custom endpoint configuration.
- Router pool.
- Usage accounting and model score updates.

### Phase 4: Research tools

- `ddgs` search.
- Safe curl extraction.
- Optional unauthenticated Jina extraction.
- Evidence and provenance storage.
- Subagent spawning.

### Phase 5: Review workflow

- First-cycle review.
- Impact analysis.
- Safe PoC generation.
- Four-agent review and quorum rules.
- Polishing and final review.
- Final report export.

### Phase 6: Web UI and observability

- Dashboard.
- Live agent activity.
- Finding workspace.
- Provider/model statistics.
- Usage and token dashboards.
- Approval center.
- Logs and exports.

### Phase 7: Hardening

- Security testing.
- Recovery testing.
- Load testing.
- Documentation.
- Packaging for Linux.
- Reproducible installation and upgrade path.

---

## 21. Definition of Done

The system is ready for an initial release when:

- It runs on supported Linux environments through a documented installation process.
- The CLI reliably launches and controls the local web UI.
- Campaign scope and authorization are mandatory and enforced at runtime.
- Multiple routers operate concurrently with failover and rate-limit awareness.
- Free-only routing cannot accidentally select a paid or unknown-status model.
- Users can configure supported providers and custom endpoints.
- Agents and subagents have UUIDs, budgets, leases, and auditable activity.
- Search and extraction preserve provenance and resist unsafe requests.
- Findings pass through the complete review lifecycle without bypassable gates.
- The four-agent PoC review, dispute handling, revert logic, and deletion safeguards work as specified.
- Final reports are versioned, evidence-linked, redacted, and exportable.
- The UI exposes active agents, current work, lifecycle state, token usage, request counts, provider/model breakdowns, health, errors, and approvals.
- Restarting the application does not lose campaign or finding state.
- Automated tests cover core correctness, safety, reliability, and provider behavior.
- Submission to an external program is never automatic and always requires explicit human approval.
