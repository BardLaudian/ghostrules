"""Command line interface."""

from __future__ import annotations

import typer

from ghostrules import __version__

app = typer.Typer(
    name="ghostrules",
    help="Find the instructions your AI agent sees but you don't.",
    no_args_is_help=True,
    add_completion=False,
)


@app.callback()
def main() -> None:
    """Find the instructions your AI agent sees but you don't."""


@app.command()
def version() -> None:
    """Print the ghostrules version."""
    typer.echo(f"ghostrules {__version__}")
