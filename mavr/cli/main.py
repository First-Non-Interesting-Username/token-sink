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
logs_app = typer.Typer(help="View structured logs and diagnostics.", no_args_is_help=True)

app.add_typer(init_app, name="init")
app.add_typer(doctor_app, name="doctor")
app.add_typer(serve_app, name="serve")
app.add_typer(campaign_app, name="campaign")
app.add_typer(provider_app, name="provider")
app.add_typer(model_app, name="model")
app.add_typer(finding_app, name="finding")
app.add_typer(report_app, name="report")
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
def serve_run() -> None:
    """Start the local API and UI server."""
    _not_implemented("system serve")


@campaign_app.command("list")
def campaign_list() -> None:
    """List campaigns."""
    _not_implemented("system campaign list")


@campaign_app.command("new")
def campaign_new() -> None:
    """Create a new campaign."""
    _not_implemented("system campaign new")


@campaign_app.command("show")
def campaign_show() -> None:
    """Show campaign details."""
    _not_implemented("system campaign show")


@campaign_app.command("export")
def campaign_export() -> None:
    """Export a campaign run bundle."""
    _not_implemented("system campaign export")


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
def finding_list() -> None:
    """List findings."""
    _not_implemented("system finding list")


@finding_app.command("show")
def finding_show() -> None:
    """Show finding details."""
    _not_implemented("system finding show")


@report_app.command("show")
def report_show() -> None:
    """Show a final report."""
    _not_implemented("system report show")


@report_app.command("submit")
def report_submit() -> None:
    """Submit a final report (requires human approval)."""
    _not_implemented("system report submit")


@logs_app.command("tail")
def logs_tail() -> None:
    """Tail structured logs."""
    _not_implemented("system logs tail")


@logs_app.command("export")
def logs_export() -> None:
    """Export redacted logs."""
    _not_implemented("system logs export")


if __name__ == "__main__":
    app()
