"""Top-level CLI application with subcommand groups.

Phase 1: skeleton only. Subcommands print a placeholder and exit.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

import typer
from rich.console import Console

console = Console()


def _version_callback(value: bool) -> None:
    if value:
        from mavr import __version__

        typer.echo(f"mavr {__version__}")
        raise typer.Exit()


app = typer.Typer(
    name="system",
    help="MAVR: Multi-Agent Security Vulnerability Research System.",
    no_args_is_help=True,
    add_completion=False,
    invoke_without_command=True,
)

init_app = typer.Typer(help="Initialize configuration and local data directories.", no_args_is_help=True)
doctor_app = typer.Typer(help="Run diagnostics on the local installation.", no_args_is_help=True)
serve_app = typer.Typer(help="Start the local API and UI server.", no_args_is_help=True)
campaign_app = typer.Typer(help="Manage research campaigns.", no_args_is_help=True)
provider_app = typer.Typer(help="Inspect and test providers.", no_args_is_help=True)
model_app = typer.Typer(help="Inspect models and run benchmarks.", no_args_is_help=True)
finding_app = typer.Typer(help="Inspect and manage findings.", no_args_is_help=True)
report_app = typer.Typer(help="Export and submit final reports.", no_args_is_help=True)
approval_app = typer.Typer(help="Mint and revoke human-approval tokens.", no_args_is_help=True)
logs_app = typer.Typer(help="View structured logs and diagnostics.", no_args_is_help=True)

app.add_typer(init_app, name="init")
app.add_typer(doctor_app, name="doctor")
app.add_typer(serve_app, name="serve")
app.add_typer(campaign_app, name="campaign")
app.add_typer(provider_app, name="provider")
app.add_typer(model_app, name="model")
app.add_typer(finding_app, name="finding")
app.add_typer(report_app, name="report")
app.add_typer(approval_app, name="approval")
app.add_typer(logs_app, name="logs")


@app.callback()
def _root(
    version: bool = typer.Option(
        False,
        "--version",
        callback=_version_callback,
        is_eager=True,
        help="Show version and exit.",
    ),
) -> None:
    """MAVR root command."""


def _not_implemented(cmd: str) -> None:
    console.print(f"[yellow]{cmd}[/yellow] is not yet implemented (Phase 1 skeleton).")


def _resolve_config_or_exit(path: str | None):
    from mavr.config.loader import load_config
    try:
        return load_config(path)
    except Exception as exc:  # noqa: BLE001 — surface any validation failure
        console.print(f"[red]config error:[/red] {exc}")
        raise typer.Exit(code=2) from exc


@init_app.command("run")
def init_run(
    config: str | None = typer.Option(None, "--config", help="Path to user config overlay."),
) -> None:
    """Initialize MAVR config directory, default config, and database."""
    from pathlib import Path

    from mavr.config.loader import _user_config_path
    from mavr.observability.logging import configure_logging
    from mavr.storage.artifacts import ArtifactStore
    from mavr.storage.database import Database, apply_migrations, expand_db_path

    cfg = _resolve_config_or_exit(config)
    configure_logging(level=cfg.logging.level, json=cfg.logging.json_output)

    # 1. user config dir + default overlay (write the default once)
    user_cfg = _user_config_path() if config is None else Path(config).expanduser()
    user_cfg.parent.mkdir(parents=True, exist_ok=True)
    if not user_cfg.exists():
        # minimal overlay that just references the defaults; user can extend
        user_cfg.write_text("# MAVR user config overlay\n# This file is optional and may be empty.\n", encoding="utf-8")
        console.print(f"[green]created user config:[/green] {user_cfg}")
    else:
        console.print(f"[blue]user config exists:[/blue] {user_cfg}")

    # 2. storage dirs
    db_path = expand_db_path(cfg.storage.db_path)
    artifacts = ArtifactStore(cfg.storage.artifact_dir)
    console.print(f"[green]db path:[/green] {db_path}")
    console.print(f"[green]artifact dir:[/green] {artifacts.root}")

    # 3. migrations
    db = Database(db_path)
    applied = asyncio_run(apply_migrations(db, "up"))
    if applied:
        console.print(f"[green]applied migrations:[/green] {applied}")
    else:
        console.print("[blue]migrations already up to date[/blue]")

    console.print("[bold green]init complete[/bold green]")


@doctor_app.command("run")
def doctor_run(
    config: str | None = typer.Option(None, "--config", help="Path to user config overlay."),
) -> None:
    """Run local diagnostics. Exits non-zero on any failure."""
    import shutil
    import socket

    from mavr.config.loader import load_config
    from mavr.observability.logging import configure_logging
    from mavr.secrets import keyring_reachable
    from mavr.storage.artifacts import ArtifactStore
    from mavr.storage.database import Database, apply_migrations, expand_db_path

    failures: list[str] = []
    try:
        cfg = load_config(config)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]config:[/red] invalid: {exc}")
        raise typer.Exit(code=2) from exc

    configure_logging(level=cfg.logging.level, json=cfg.logging.json_output)

    def _check(name: str, ok: bool, detail: str) -> None:
        status = "[green]OK[/green]" if ok else "[red]FAIL[/red]"
        console.print(f"{status} {name}: {detail}")
        if not ok:
            failures.append(name)

    _check("config", True, "loaded and validated")

    # keyring
    ok, detail = keyring_reachable()
    _check("keyring", ok, detail)

    # db connectivity
    db_path = expand_db_path(cfg.storage.db_path)
    db = Database(db_path)
    ok, detail = asyncio_run(db.ping())
    _check("db", ok, detail)
    try:
        applied = asyncio_run(apply_migrations(db, "up"))
        _check("migrations", True, f"current ({len(applied)} newly applied)")
    except Exception as exc:  # noqa: BLE001
        _check("migrations", False, str(exc))

    # artifact dir
    try:
        store = ArtifactStore(Path(cfg.storage.artifact_dir))
        ok, detail = store.is_writable()
        _check("artifact_dir", ok, detail)
        free = store.free_bytes()
        if free < 100 * 1024 * 1024:
            failures.append("disk_space")
            console.print(f"[red]FAIL[/red] disk_space: only {free} bytes free (< 100 MiB)")
        else:
            console.print(f"[green]OK[/green] disk_space: {free} bytes free")
    except Exception as exc:  # noqa: BLE001
        _check("artifact_dir", False, str(exc))

    # port availability
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind((cfg.server.host, cfg.server.port))
        s.close()
        _check("port", True, f"{cfg.server.host}:{cfg.server.port} available")
    except OSError as exc:
        _check("port", False, f"{cfg.server.host}:{cfg.server.port} unavailable: {exc}")

    # total free disk (overall, for visibility)
    usage = shutil.disk_usage("/")
    console.print(f"[blue]disk[/blue]: total={usage.total} free={usage.free}")

    if failures:
        console.print(f"[bold red]doctor: {len(failures)} failure(s)[/bold red]")
        raise typer.Exit(code=1)
    console.print("[bold green]doctor: all checks passed[/bold green]")


def asyncio_run(coro):  # small helper to keep doctor output sync
    import asyncio as _aio
    return _aio.run(coro)


@serve_app.command("run")
def serve_run(
    config: str | None = typer.Option(None, "--config", help="Path to user config overlay."),
    host: str | None = typer.Option(None, "--host", help="Override server.host."),
    port: int | None = typer.Option(None, "--port", help="Override server.port."),
    allow_lan: bool = typer.Option(
        False, "--allow-lan", help="Bind on a non-loopback address (must pair with --human-approved)."
    ),
    human_approved: bool = typer.Option(
        False,
        "--human-approved/--no-human-approved",
        help="Explicitly confirm non-loopback binding is authorized.",
    ),
    token: str | None = typer.Option(
        None,
        "--token",
        help="Use a specific bearer token (default: auto-generated, shown once).",
    ),
    print_token: bool = typer.Option(
        True,
        "--print-token/--no-print-token",
        help="Print the bearer token to stdout on startup.",
    ),
) -> None:
    """Start the local API and UI server."""
    import uvicorn

    from mavr.api import build_app
    from mavr.observability.logging import configure_logging as _configure_logging
    from mavr.storage.database import Database, apply_migrations, expand_db_path

    cfg = _resolve_config_or_exit(config)
    _configure_logging(level=cfg.logging.level, json=cfg.logging.json_output)

    if host:
        cfg.server.host = host
    if port:
        cfg.server.port = port
    if allow_lan:
        cfg.server.allow_lan = True

    db = Database(expand_db_path(cfg.storage.db_path))
    asyncio_run(apply_migrations(db, "up"))

    app = build_app(
        config=cfg,
        db=db,
        bind_host=cfg.server.host,
        allow_lan=allow_lan,
        human_approved=human_approved,
        token=token,
    )
    if print_token:
        console.print(
            f"[bold green]MAVR serving at[/bold green] {app.url()}\n"
            f"[bold green]bearer token:[/bold green] {app.bearer_token()}\n"
            f"[yellow]keep this token secret; it is shown only once.[/yellow]"
        )
    uvicorn.run(
        app.app,
        host=cfg.server.host,
        port=cfg.server.port,
        log_level=cfg.logging.level.lower(),
        access_log=False,
    )


@campaign_app.command("list")
def campaign_list(
    config: str | None = typer.Option(None, "--config", help="Path to user config overlay."),
    limit: int = typer.Option(20, "--limit", help="Max rows to display."),
) -> None:
    """List campaigns."""
    from mavr.api import db as api_db
    from mavr.observability.logging import configure_logging as _configure_logging
    from mavr.storage.database import Database, apply_migrations, expand_db_path

    cfg = _resolve_config_or_exit(config)
    _configure_logging(level=cfg.logging.level, json=cfg.logging.json_output)
    db = Database(expand_db_path(cfg.storage.db_path))
    asyncio_run(apply_migrations(db, "up"))
    rows = asyncio_run(api_db.list_campaigns(db, limit=limit))
    if not rows:
        console.print("[blue]no campaigns[/blue]")
        return
    for r in rows:
        console.print(
            f"  [bold]{r['id'][:8]}[/bold] [{r['state']:>9}] {r['name']}"
        )


@campaign_app.command("new")
def campaign_new(
    name: str = typer.Option(..., "--name", help="Campaign name."),
    description: str = typer.Option("", "--description", help="Free-text description."),
    target: str = typer.Option(..., "--target", help="Single allowed target (host or URL)."),
    duration_hours: int = typer.Option(24, "--duration-hours", help="Max duration in hours."),
    config: str | None = typer.Option(None, "--config", help="Path to user config overlay."),
) -> None:
    """Create a new campaign."""
    from mavr.api import db as api_db
    from mavr.observability.logging import configure_logging as _configure_logging
    from mavr.storage.database import Database, apply_migrations, expand_db_path

    cfg = _resolve_config_or_exit(config)
    _configure_logging(level=cfg.logging.level, json=cfg.logging.json_output)
    db = Database(expand_db_path(cfg.storage.db_path))
    asyncio_run(apply_migrations(db, "up"))
    cid = asyncio_run(
        api_db.create_campaign(
            db,
            name=name,
            description=description,
            target_spec={"hosts": [target]},
            duration_hours=duration_hours,
        )
    )
    console.print(f"[green]created campaign[/green] id={cid}")


@campaign_app.command("show")
def campaign_show(
    campaign_id: str = typer.Argument(..., help="Campaign id."),
    config: str | None = typer.Option(None, "--config", help="Path to user config overlay."),
) -> None:
    """Show campaign details."""
    from mavr.api import db as api_db
    from mavr.observability.logging import configure_logging as _configure_logging
    from mavr.storage.database import Database, apply_migrations, expand_db_path

    cfg = _resolve_config_or_exit(config)
    _configure_logging(level=cfg.logging.level, json=cfg.logging.json_output)
    db = Database(expand_db_path(cfg.storage.db_path))
    asyncio_run(apply_migrations(db, "up"))

    async def _run() -> dict[str, Any]:
        campaign = await api_db.get_campaign(db, campaign_id)
        if campaign is None:
            return {}
        scope = await api_db.get_scope_policy(db, campaign_id)
        agents = await api_db.list_agents(db, campaign_id=campaign_id, limit=200)
        tasks = await api_db.list_tasks(db, campaign_id=campaign_id, limit=200)
        findings = await api_db.list_findings(db, campaign_id=campaign_id, limit=200)
        return {
            "campaign": campaign,
            "scope": scope,
            "agents": agents,
            "tasks": tasks,
            "findings": findings,
        }

    data = asyncio_run(_run())
    if not data:
        console.print(f"[red]campaign {campaign_id} not found[/red]")
        raise typer.Exit(code=1)
    c = data["campaign"]
    console.print(
        f"[bold]{c['name']}[/bold] ({c['id']})\n"
        f"  state={c['state']}  human_approved={c['human_approved']}  "
        f"duration={c['duration_hours']}h"
    )
    if data["scope"]:
        s = data["scope"]
        console.print(
            f"  scope: active_testing={s.get('active_testing')} "
            f"targets={s.get('allowed_targets')} methods={s.get('allowed_methods')}"
        )
    console.print(
        f"  agents={len(data['agents'])}  tasks={len(data['tasks'])}  "
        f"findings={len(data['findings'])}"
    )


@campaign_app.command("export")
def campaign_export(
    campaign_id: str = typer.Argument(..., help="Campaign id."),
    output: str | None = typer.Option(None, "--output", "-o", help="Output zip path."),
    config: str | None = typer.Option(None, "--config", help="Path to user config overlay."),
) -> None:
    """Export a redacted run bundle for the campaign."""
    from mavr.observability.bundle import export_run_bundle
    from mavr.observability.logging import configure_logging as _configure_logging
    from mavr.storage.database import Database, apply_migrations, expand_db_path

    cfg = _resolve_config_or_exit(config)
    _configure_logging(level=cfg.logging.level, json=cfg.logging.json_output)
    db = Database(expand_db_path(cfg.storage.db_path))
    asyncio_run(apply_migrations(db, "up"))
    out = Path(output).expanduser() if output else (
        Path(cfg.storage.artifact_dir).expanduser() / "bundles" / f"{campaign_id}.zip"
    )
    result = asyncio_run(
        export_run_bundle(
            db,
            campaign_id=campaign_id,
            output_path=out,
            config_snapshot=cfg,
        )
    )
    console.print(
        f"[green]exported run bundle[/green]\n"
        f"  path={result.path}\n"
        f"  size={result.size_bytes} bytes\n"
        f"  entries={result.entry_count}"
    )


@provider_app.command("list")
def provider_list(
    config: str | None = typer.Option(None, "--config", help="Path to user config overlay."),
) -> None:
    """List configured providers (native free, gateways, and custom endpoints)."""
    from mavr.config.loader import _user_config_path
    from mavr.observability.logging import configure_logging as _configure_logging
    from mavr.providers.registry import ProviderRegistry

    cfg = _resolve_config_or_exit(config)
    _configure_logging(level=cfg.logging.level, json=cfg.logging.json_output)
    overlay = _user_config_path() if config is None else config
    console.print(f"[blue]config[/blue]: {overlay}")

    registry = ProviderRegistry.default()
    try:
        for summary in registry.list():
            free_tag = "[green]free[/green]" if summary.free else "[yellow]paid/unknown[/yellow]"
            auth_color = {
                "ok": "green",
                "missing": "yellow",
                "invalid": "red",
            }.get(summary.auth_status, "white")
            console.print(
                f"  [bold]{summary.provider_id}[/bold] "
                f"({summary.kind}, {free_tag}, auth=[{auth_color}]{summary.auth_status}[/{auth_color}]) — "
                f"{summary.model_count} model(s) | {summary.display_name}"
            )
    finally:
        asyncio_run(registry.aclose())


@provider_app.command("test")
def provider_test(
    provider_id: str = typer.Argument(..., help="Provider id, e.g. gemini or huggingface."),
    config: str | None = typer.Option(None, "--config", help="Path to user config overlay."),
) -> None:
    """Run a connectivity + auth probe against a single provider.

    Never logs the secret. The exit code is 0 on success, 1 on failure.
    """
    from mavr.observability.logging import configure_logging as _configure_logging
    from mavr.providers.registry import ProviderRegistry

    cfg = _resolve_config_or_exit(config)
    _configure_logging(level=cfg.logging.level, json=cfg.logging.json_output)

    registry = ProviderRegistry.default()
    try:
        if not registry.has(provider_id):
            console.print(f"[red]unknown provider:[/red] {provider_id}")
            raise typer.Exit(code=2)
        report = asyncio_run(registry.health(provider_id))
        auth_color = {
            "ok": "green",
            "missing": "yellow",
            "invalid": "red",
        }.get(report.auth_status, "white")
        status = "[green]OK[/green]" if report.ok else "[red]FAIL[/red]"
        console.print(
            f"{status} [bold]{provider_id}[/bold]: auth=[{auth_color}]{report.auth_status}[/{auth_color}] "
            f"latency={report.latency_ms}ms detail={report.detail}"
        )
        if not report.ok:
            raise typer.Exit(code=1)
    finally:
        asyncio_run(registry.aclose())


@model_app.command("list")
def model_list(
    config: str | None = typer.Option(None, "--config", help="Path to user config overlay."),
) -> None:
    """List all known models with their free status and capabilities."""
    from mavr.observability.logging import configure_logging as _configure_logging
    from mavr.providers.registry import ProviderRegistry

    cfg = _resolve_config_or_exit(config)
    _configure_logging(level=cfg.logging.level, json=cfg.logging.json_output)

    registry = ProviderRegistry.default()
    try:
        for adapter in registry.all():  # type: ignore[attr-defined]
            for entry in adapter.models():
                free_tag = (
                    "[green]free[/green]"
                    if entry.free and entry.free_status == "confirmed"
                    else f"[yellow]{entry.free_status}[/yellow]"
                )
                console.print(
                    f"  [bold]{entry.provider_id}[/bold]/[cyan]{entry.model_key}[/cyan] "
                    f"({free_tag}, ctx={entry.context_limit}, stream={entry.streaming}) — "
                    f"{entry.display_name}"
                )
    finally:
        asyncio_run(registry.aclose())


@model_app.command("benchmark")
def model_benchmark(
    config: str | None = typer.Option(None, "--config", help="Path to user config overlay."),
    provider: str | None = typer.Option(
        None,
        "--provider",
        help="Comma-separated list of provider ids to benchmark. Defaults to all.",
    ),
    mock: bool = typer.Option(
        True,
        "--mock/--no-mock",
        help="Use an in-process mock adapter instead of real providers (default: mock).",
    ),
) -> None:
    """Run the offline benchmark suite and persist scores.

    By default the benchmark runs against a mock adapter so the suite
    is reproducible in CI. Pass --no-mock to run against real
    providers; you must have valid secrets configured.
    """
    from mavr.providers.model_benchmark import BenchmarkRunner
    from mavr.providers.model_catalog import ModelScoreStore
    from mavr.providers.registry import ProviderRegistry
    from mavr.storage.database import Database, apply_migrations, expand_db_path

    cfg = _resolve_config_or_exit(config)
    from mavr.observability.logging import configure_logging as _configure_logging

    _configure_logging(level=cfg.logging.level, json=cfg.logging.json_output)

    db = Database(expand_db_path(cfg.storage.db_path))
    asyncio_run(apply_migrations(db, "up"))
    scores = ModelScoreStore(db)

    registry = ProviderRegistry.default()
    try:
        targets: list[tuple[str, str, Any]] = []
        if mock:
            from mavr.tests._fakes import MockAdapter

            mock_adapter = MockAdapter()
            for entry in mock_adapter.models():
                targets.append((entry.provider_id, entry.model_key, mock_adapter.chat))
        else:
            if provider:
                chosen = {p.strip() for p in provider.split(",") if p.strip()}
            else:
                chosen = {a.provider_id for a in registry.all()}  # type: ignore[attr-defined]
            for adapter in registry.all():  # type: ignore[attr-defined]
                if adapter.provider_id not in chosen:
                    continue
                for entry in adapter.models():
                    targets.append((entry.provider_id, entry.model_key, adapter.chat))

        runner = BenchmarkRunner(db, scores)
        run_id = asyncio_run(runner.run(targets, actor_kind="human", actor_id="cli", notes="cli benchmark"))
        console.print(f"[green]benchmark complete[/green] run_id={run_id}")
        for s in asyncio_run(scores.all()):
            console.print(
                f"  [bold]{s.provider_id}[/bold]/[cyan]{s.model_key}[/cyan] "
                f"category={s.category.value} score={s.score:.2f} samples={s.sample_count}"
            )
    finally:
        asyncio_run(registry.aclose())


@finding_app.command("list")
def finding_list(
    config: str | None = typer.Option(None, "--config", help="Path to user config overlay."),
    campaign: str | None = typer.Option(None, "--campaign", help="Filter by campaign id."),
    state: str | None = typer.Option(None, "--state", help="Filter by finding state."),
    limit: int = typer.Option(20, "--limit", help="Max rows to display."),
) -> None:
    """List findings (most recent first)."""

    from mavr.observability.logging import configure_logging as _configure_logging
    from mavr.storage.database import Database, apply_migrations, expand_db_path

    cfg = _resolve_config_or_exit(config)
    _configure_logging(level=cfg.logging.level, json=cfg.logging.json_output)
    db = Database(expand_db_path(cfg.storage.db_path))
    asyncio_run(apply_migrations(db, "up"))

    async def _run() -> list[dict[str, Any]]:
        async with db.acquire() as conn:
            sql = (
                "SELECT id, campaign_id, title, state, severity, confidence, "
                "current_version, tombstoned, updated_at FROM findings "
            )
            clauses: list[str] = []
            params: list[Any] = []
            if campaign:
                clauses.append("campaign_id = ?")
                params.append(campaign)
            if state:
                clauses.append("state = ?")
                params.append(state)
            if clauses:
                sql += "WHERE " + " AND ".join(clauses) + " "
            sql += "ORDER BY updated_at DESC LIMIT ?"
            params.append(limit)
            cur = await conn.execute(sql, params)
            return [dict(r) for r in await cur.fetchall()]

    rows = asyncio_run(_run())
    if not rows:
        console.print("[blue]no findings[/blue]")
        return
    for r in rows:
        sev = r["severity"] or "-"
        tomb = " [red](tombstoned)[/red]" if r["tombstoned"] else ""
        console.print(
            f"  [bold]{r['id'][:8]}[/bold] [{r['state']}] {sev:>8} v{r['current_version']} "
            f"c={r['confidence'] or '-':>12} {r['title']}{tomb}"
        )


@finding_app.command("show")
def finding_show(
    finding_id: str = typer.Argument(..., help="Finding UUID."),
    config: str | None = typer.Option(None, "--config", help="Path to user config overlay."),
) -> None:
    """Show a single finding, its history, versions, and reviews."""

    from mavr.findings import lifecycle
    from mavr.findings import reviews as reviews_mod
    from mavr.findings.workflow import list_all_reviews
    from mavr.observability.logging import configure_logging as _configure_logging
    from mavr.storage.database import Database, apply_migrations, expand_db_path

    cfg = _resolve_config_or_exit(config)
    _configure_logging(level=cfg.logging.level, json=cfg.logging.json_output)
    db = Database(expand_db_path(cfg.storage.db_path))
    asyncio_run(apply_migrations(db, "up"))

    async def _run() -> dict[str, Any]:
        async with db.acquire() as conn:
            finding = await lifecycle.get(conn, finding_id)
            if finding is None:
                return {"_missing": True}
            history = await lifecycle.history(conn, finding_id)
            reviews = await list_all_reviews(conn, finding_id)
            summaries: list[reviews_mod.ReviewSummary] = []
            for r in reviews:
                s = await reviews_mod.get_summary(
                    conn, finding_id=finding_id, version=r.version, mode="independent_first"
                )
                if s is not None:
                    summaries.append(s)
            return {
                "finding": finding,
                "history": history,
                "reviews": reviews,
                "summaries": summaries,
            }

    out = asyncio_run(_run())
    if out.get("_missing"):
        console.print(f"[red]finding {finding_id} not found[/red]")
        raise typer.Exit(code=1)
    f = out["finding"]
    console.print(
        f"[bold]{f.title}[/bold] ({f.id})\n"
        f"  state={f.state.value}  severity={f.severity.value if f.severity else '-'}  "
        f"confidence={f.confidence or '-'}  v{f.current_version}"
        f"{'  [red]TOMBSTONED[/red]' if f.tombstoned else ''}"
    )
    if out["history"]:
        console.print("  [bold]history:[/bold]")
        for h in out["history"]:
            console.print(
                f"    {h['created_at']}  {h['prior_state']} -> {h['new_state']}  "
                f"by {h['actor_kind']}:{h['actor_id'] or '-'}  {h['reason']}"
            )
    if out["reviews"]:
        console.print("  [bold]reviews:[/bold]")
        for r in out["reviews"]:
            console.print(
                f"    v{r.version}  {r.verdict.value:>16}  validity={r.validity}  "
                f"scope_safety={r.scope_safety}  by {r.reviewer_agent_id[:8]}"
            )
    for s in out["summaries"]:
        console.print(
            f"  [bold]summary v{s.version}[/bold] mode={s.mode} quorum={s.quorum_policy} "
            f"accept={s.accept_count}/reject={s.reject_count}/changes={s.request_changes_count} "
            f"outcome={s.outcome}"
        )


@report_app.command("show")
def report_show(
    finding_id: str = typer.Argument(..., help="Finding UUID."),
    config: str | None = typer.Option(None, "--config", help="Path to user config overlay."),
) -> None:
    """Show the final report paths and hash manifest for a finding."""

    from mavr.observability.logging import configure_logging as _configure_logging
    from mavr.storage.database import Database, apply_migrations, expand_db_path

    cfg = _resolve_config_or_exit(config)
    _configure_logging(level=cfg.logging.level, json=cfg.logging.json_output)
    db = Database(expand_db_path(cfg.storage.db_path))
    asyncio_run(apply_migrations(db, "up"))

    async def _run() -> list[Any]:
        async with db.acquire() as conn:
            cur = await conn.execute(
                "SELECT version, report_path, evidence_manifest_path, "
                "redaction_manifest_path, hash_manifest, created_at "
                "FROM final_reports WHERE finding_id = ? ORDER BY version",
                (finding_id,),
            )
            return list(await cur.fetchall())

    rows = asyncio_run(_run())
    if not rows:
        console.print("[blue]no final reports yet[/blue]")
        return
    for r in rows:
        console.print(
            f"  v{r['version']}  report={r['report_path']}\n"
            f"    evidence={r['evidence_manifest_path']}\n"
            f"    redaction={r['redaction_manifest_path']}\n"
            f"    hash={r['hash_manifest']}  created={r['created_at']}"
        )


@report_app.command("submit")
def report_submit(
    finding_id: str = typer.Argument(..., help="Finding UUID."),
    version: int = typer.Argument(..., help="Finding version."),
    approval_token: str = typer.Option(
        ..., "--approval-token", help="Token from `system approval create`."
    ),
    human_approved: bool = typer.Option(
        False,
        "--human-approved/--no-human-approved",
        help="Explicitly confirm you typed a real approval token.",
    ),
    transport: str = typer.Option(
        "manifest_only",
        "--transport",
        help="manifest_only (safe, default) or http (opt-in per campaign).",
    ),
    target: str = typer.Option(
        "manifest-only", "--target", help="Submission target URL or label."
    ),
    output_dir: str | None = typer.Option(
        None, "--output-dir", help="Override the report output directory."
    ),
    config: str | None = typer.Option(None, "--config", help="Path to user config overlay."),
) -> None:
    """Submit a finalized finding. NEVER automatic; requires an approval token."""

    from mavr.observability.logging import configure_logging as _configure_logging
    from mavr.reports import SubmissionError, submit
    from mavr.storage.database import Database, apply_migrations, expand_db_path

    if not human_approved:
        console.print(
            "[red]refusing to submit without --human-approved.[/red]\n"
            "MAVR never submits automatically. Pass --human-approved to confirm.",
        )
        raise typer.Exit(code=2)

    cfg = _resolve_config_or_exit(config)
    _configure_logging(level=cfg.logging.level, json=cfg.logging.json_output)
    db = Database(expand_db_path(cfg.storage.db_path))
    asyncio_run(apply_migrations(db, "up"))
    out_dir = output_dir or cfg.storage.artifact_dir

    async def _run() -> Any:
        async with db.acquire() as conn:
            return await submit(
                conn,
                finding_id=finding_id,
                version=version,
                approval_token=approval_token,
                output_dir=out_dir,
                transport=transport,
                target=target,
                human_approved=True,
            )

    try:
        result = asyncio_run(_run())
    except SubmissionError as exc:
        console.print(f"[red]submission refused:[/red] {exc}")
        raise typer.Exit(code=1) from exc
    console.print(
        f"[green]submission recorded[/green]\n"
        f"  manifest={result.manifest_path}\n"
        f"  transport={result.transport}  target={result.target}\n"
        f"  response_status={result.response_status}\n"
        f"  approval_id={result.approval_id}\n"
        f"  submitted_at={result.submitted_at.isoformat()}"
    )


@approval_app.command("create")
def approval_create(
    action: str = typer.Option(
        ...,
        "--action",
        help="active_testing | submission | scope_change | deletion",
    ),
    actor: str = typer.Option(..., "--actor", help="Your identity (e.g. email or 'human')."),
    campaign: str | None = typer.Option(None, "--campaign", help="Campaign id (optional)."),
    finding: str | None = typer.Option(None, "--finding", help="Finding id (optional)."),
    reason: str = typer.Option("", "--reason", help="Why you're approving this action."),
    ttl: int = typer.Option(900, "--ttl", help="Token TTL in seconds (max 86400)."),
    config: str | None = typer.Option(None, "--config", help="Path to user config overlay."),
) -> None:
    """Mint a human approval token for a privileged action."""

    from mavr import approvals as approvals_mod
    from mavr.observability.logging import configure_logging as _configure_logging
    from mavr.storage.database import Database, apply_migrations, expand_db_path

    cfg = _resolve_config_or_exit(config)
    _configure_logging(level=cfg.logging.level, json=cfg.logging.json_output)
    db = Database(expand_db_path(cfg.storage.db_path))
    asyncio_run(apply_migrations(db, "up"))

    async def _run() -> approvals_mod.Approval:
        async with db.acquire() as conn:
            return await approvals_mod.create(
                conn,
                action=action,
                actor=actor,
                reason=reason,
                campaign_id=campaign,
                finding_id=finding,
                ttl_seconds=ttl,
            )

    approval = asyncio_run(_run())
    console.print(
        f"[green]approval token minted[/green]\n"
        f"  id={approval.id}\n"
        f"  action={approval.action}\n"
        f"  actor={approval.actor}\n"
        f"  expires_at={approval.expires_at.isoformat()}\n"
        f"  token={approval.token}\n"
        f"  [yellow]Use this token once. It is consumed on use and cannot be replayed.[/yellow]"
    )


@logs_app.command("tail")
def logs_tail(
    config: str | None = typer.Option(None, "--config", help="Path to user config overlay."),
    last_id: int = typer.Option(0, "--last-id", help="Start after this event id (default 0)."),
    follow: bool = typer.Option(
        True, "--follow/--no-follow", help="Continue tailing the live event stream."
    ),
    interval: float = typer.Option(1.0, "--interval", help="Polling interval in seconds."),
) -> None:
    """Tail the structured event bus."""
    from mavr.observability.events import EventBus
    from mavr.observability.logging import configure_logging as _configure_logging
    from mavr.storage.database import Database, apply_migrations, expand_db_path

    cfg = _resolve_config_or_exit(config)
    _configure_logging(level=cfg.logging.level, json=cfg.logging.json_output)
    db = Database(expand_db_path(cfg.storage.db_path))
    asyncio_run(apply_migrations(db, "up"))
    bus = EventBus(db)
    seen = int(last_id)
    if seen == 0:
        # Seed with the latest 20 so the user sees context.
        seed = asyncio_run(bus.latest(20))
        for e in seed:
            console.print(
                f"[{e.severity:>7}] id={e.id:>6} {e.created_at} {e.event_type} {e.payload}"
            )
            seen = max(seen, e.id)
    import time as _time

    try:
        while True:
            tail = asyncio_run(bus.list_since(seen, limit=200))
            for e in tail:
                console.print(
                    f"[{e.severity:>7}] id={e.id:>6} {e.created_at} {e.event_type} {e.payload}"
                )
                seen = max(seen, e.id)
            if not follow:
                break
            _time.sleep(max(0.1, float(interval)))
    except KeyboardInterrupt:
        return


@logs_app.command("export")
def logs_export(
    output: str = typer.Option(..., "--output", "-o", help="Output JSONL path."),
    config: str | None = typer.Option(None, "--config", help="Path to user config overlay."),
    campaign_id: str | None = typer.Option(None, "--campaign", help="Filter by campaign id."),
) -> None:
    """Export a redacted JSONL of all events (or those for one campaign)."""
    import json as _json

    from mavr.observability.events import EventBus
    from mavr.observability.logging import configure_logging as _configure_logging
    from mavr.storage.database import Database, apply_migrations, expand_db_path

    cfg = _resolve_config_or_exit(config)
    _configure_logging(level=cfg.logging.level, json=cfg.logging.json_output)
    db = Database(expand_db_path(cfg.storage.db_path))
    asyncio_run(apply_migrations(db, "up"))
    bus = EventBus(db)
    out_path = Path(output).expanduser()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    seen = 0
    written = 0
    with out_path.open("w", encoding="utf-8") as fh:
        while True:
            batch = asyncio_run(bus.list_since(seen, limit=500))
            if not batch:
                break
            for e in batch:
                if campaign_id is not None and e.campaign_id != campaign_id:
                    continue
                fh.write(_json.dumps(e.to_sse(), ensure_ascii=False) + "\n")
                written += 1
                seen = max(seen, e.id)
    console.print(f"[green]wrote {written} events[/green] to {out_path}")


if __name__ == "__main__":
    app()
