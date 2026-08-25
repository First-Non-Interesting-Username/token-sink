# AGENTS.md

Working rules and links for AI agents in this repo. **Keep this file minimal —
processes live in `docs/`, not here.**

## Links

- [PLAN.md](PLAN.md) — the full implementation plan this repo exists to build
  (product behavior, architecture, safety controls, acceptance criteria).
  Read it before doing anything; it is the source of truth for what we are
  building.
- README.md — repo overview (add one once real code lands).

## Working rules

- **NEVER commit to `main` directly.** Branch → PR; merge ONLY after CI is
  green on the PR (once workflows exist, all required checks must pass).
  Applies to agents too. The agent opens AND merges its own PRs — do not wait
  for the user to merge; verify checks are green first, then squash-merge.
  (Bootstrap commits that only add docs/agent tooling may go straight to
  `main` while the project has no CI yet.)
- **Delete the branch after the PR is merged.** Stale remote branches pile up
  fast when agents sweep PRs in batches, and a long branch list is the single
  most common thing that makes a future agent pick a stale base by mistake.
  Pass `--delete-branch` to `gh pr merge` for every merge (agent- or
  human-opened) — do not leave a branch behind "to clean up later".
- **Read PR comments before merging.** Before merging any PR, read all review
  comments and conversation threads on the PR and address or explicitly
  acknowledge them. Do not squash-merge over unresolved feedback — green CI is
  necessary but not sufficient.
- **Tag every PR comment with a per-session UUID.** When an agent posts a
  review comment, issue reply, or any other comment on a PR, prefix the body
  with `[agent:<uuid>]` (one UUID generated at session start, reused for every
  comment that session posts). Different agent sessions share the same GitHub
  account and need to distinguish their threads. Human comments do not need a
  tag.
- Always work on a fresh clone: clone a clean copy from GitHub into a
  temporary directory, do all work there, and delete it once your PR is
  merged. Never reuse or modify a stale checkout.
- Update AGENTS.md whenever structure or conventions change — stale guidance
  costs more than missing guidance.

## Documentation rules

- **Document everything that might be useful in the future.** Code should be
  self-documenting (or carry inline comments), but anything that cannot live
  in the code itself MUST be documented somewhere durable: repo layout and why
  it is shaped that way, non-obvious conventions, and decisions with their
  reasoning. If a future agent would have to reverse-engineer it, write it
  down.
- **Diversify docs — no monolith files.** Split documentation by topic across
  `docs/` instead of growing single multi-thousand-line files. A doc file
  approaching ~1000 lines should be split by concern; link related docs from
  AGENTS.md so they stay discoverable. As components land (orchestrator,
  router pool, provider adapters, web UI), give each its own doc.
- **Comment your code.** Non-trivial logic gets a short comment explaining
  WHY, not just what.

## Safety (project-specific)

This repo builds a security-research orchestration system. Its own PLAN.md
safety principles apply to how agents work on the code too:

- The tool must only ever operate against explicitly authorized, in-scope
  targets. Never weaken scope checks, approval gates, or policy blocks to make
  a test or feature easier.
- Do not commit real credentials, API keys, or tokens. Example/placeholder
  files with fake values (e.g. `sk-example-...`, `changeme`) are fine and
  encouraged for docs; just never use a live secret value.
