# token-sink

A multi-agent security vulnerability research system for the
[Hack Club Security](https://security.hackclub.com/) program: a Linux-only CLI
application that launches a locally hosted web UI coordinating multiple AI
agents that discover, validate, document, and report security vulnerabilities.

The system is designed to produce accurate, reproducible, well-evidenced
vulnerability reports — favoring correctness, safe testing, and human review
over volume. Research is restricted to explicitly authorized, in-scope targets;
out-of-scope or destructive actions are blocked by policy enforcement, not just
prompt discouragement.

## Status

Planning stage. There is no implementation yet — see [PLAN.md](PLAN.md) for the
full implementation plan (product behavior, architecture, safety controls,
acceptance criteria) and its phased roadmap.

## For AI agents

Working rules, conventions, and PR process live in [AGENTS.md](AGENTS.md).
Read it — and all of PLAN.md — before doing anything in this repo.

## Safety / scope disclaimer

This tool must only ever operate against explicitly authorized, in-scope
targets. It is built for authorized vulnerability disclosure work (e.g.
bug bounty programs with clear rules). Using it against systems you are not
authorized to test is prohibited and unsupported.

## Layout

See [docs/repo-layout.md](docs/repo-layout.md) and PLAN.md §4.
