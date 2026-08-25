"""Top-level CLI application with subcommand groups.

Phase 1: skeleton only. Subcommands print a placeholder and exit.
"""
from __future__ import annotations

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


@init_app.command("run")
def init_run() -> None:
    """Initialize MAVR config directory, default config, and database."""
    _not_implemented("system init")


@doctor_app.command("run")
def doctor_run() -> None:
    """Run local diagnostics."""
    _not_implemented("system doctor")


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
def provider_list() -> None:
    """List configured providers."""
    _not_implemented("system provider list")


@provider_app.command("test")
def provider_test() -> None:
    """Test a provider."""
    _not_implemented("system provider test")


@model_app.command("list")
def model_list() -> None:
    """List available models."""
    _not_implemented("system model list")


@model_app.command("benchmark")
def model_benchmark() -> None:
    """Run the internal model benchmark suite."""
    _not_implemented("system model benchmark")


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
