# token-sink

A multi-agent security vulnerability research system: a Linux-only CLI
application that launches a locally hosted web UI for coordinating multiple AI
agents that discover, validate, document, and report security vulnerabilities
for authorized submission to the [Hack Club Security](https://security.hackclub.com/)
program.

## Status

**Planning stage.** There is no implementation yet — the repository currently
contains the full implementation plan and working rules:

- [PLAN.md](PLAN.md) — the complete implementation plan (product behavior,
  architecture, safety controls, phased delivery). This is the source of truth
  for what we are building.
- [AGENTS.md](AGENTS.md) — working rules for AI agents contributing to this
  repository. Read it before doing anything here.
- Open issues track the planned subsystems; Phase 1 work per PLAN.md §20 has
  not landed yet.

## For agents working on this repo

Start with [AGENTS.md](AGENTS.md) for the working rules (branch/PR workflow,
review gates, comment tagging), then read [PLAN.md](PLAN.md) before picking up
an issue.

## Safety / scope disclaimer

This tool must only ever operate against explicitly authorized, in-scope
targets (e.g. a bug-bounty program's stated scope, such as Hack Club
Security). Research without an explicit authorization reference and defined
scope is out of the question by design: scope checks, approval gates, and
policy blocks are enforced by code, not by prompt encouragement. Do not use
this system against any target you are not explicitly authorized to test.
