Directory structure follows PLAN.md §4. Every Python package carries an
`__init__.py` whose docstring states its responsibility and PLAN section.
Non-package directories (`tests`, `docs`, `examples`, `migrations`,
`config`, `scripts`) are kept as plain dirs with `.gitkeep` until real
content lands.

Deviations from §4: none — the layout matches the plan verbatim. Top-level
packages (rather than a single `src/<app>` tree) were chosen deliberately to
match the plan's module-boundary requirement so providers, agent roles,
storage engines, and UI components can be replaced independently.

## tools/ (issue #155)

Tool permission registry & enforcement: `ToolRegistry` (versioned tool
signatures, single source of truth) and `ToolGate` (the only path from a
model's tool call to execution — validate first, structured rejections,
per-agent/model violation breaker). See docs/tool-contract.md.
