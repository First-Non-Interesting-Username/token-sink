# Repo Layout

Directory structure follows PLAN.md §4. Every Python package carries an
`__init__.py` whose docstring states its responsibility and PLAN section.
Non-package directories (`tests`, `docs`, `examples`, `migrations`,
`config`, `scripts`) are kept as plain dirs with `.gitkeep` until real
content lands.

Deviations from §4: none — the layout matches the plan verbatim. Top-level
packages (rather than a single `src/<app>` tree) were chosen deliberately to
match the plan's module-boundary requirement so providers, agent roles,
storage engines, and UI components can be replaced independently.
