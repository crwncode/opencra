"""First-run and post-install usage tips. PyPI cannot print after install."""

from __future__ import annotations

from pathlib import Path

from rich.console import Console

from opencra_cli.paths import first_run_marker_path

USAGE_EPILOG = (
    "Try: opencra scan .   ·   opencra doctor   ·   opencra kev refresh   ·   opencra --help"
)

USAGE_GUIDE = """\
[bold]OpenCRA is ready.[/bold] Next commands:

  [cyan]opencra scan .[/cyan]          Scan this directory
  [cyan]opencra doctor[/cyan]          Check Syft, cache, and PDF
  [cyan]opencra kev refresh[/cyan]     Update the CISA KEV catalog
  [cyan]opencra --help[/cyan]          All commands

[dim]Syft is downloaded automatically on the first online directory scan.[/dim]"""


def mark_first_run_done() -> Path:
    """Create the first-run marker so the usage tip is not shown again."""
    path = first_run_marker_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        path.write_text("", encoding="utf-8")
    return path


def first_run_pending() -> bool:
    return not first_run_marker_path().is_file()


def print_usage_guide(console: Console) -> None:
    console.print(USAGE_GUIDE)
    mark_first_run_done()


def maybe_print_first_run(console: Console, *, quiet: bool = False) -> bool:
    """Print the one-time usage tip. Returns True if it was printed."""
    if quiet or not first_run_pending():
        return False
    print_usage_guide(console)
    return True


def print_post_syft_install_tip(console: Console, path: Path) -> None:
    """Short tip after the first managed Syft install."""
    console.print(f"[green]Syft installed[/green] to {path}")
    console.print(
        "  Next: [cyan]opencra scan .[/cyan]   ·   [cyan]opencra doctor[/cyan]   "
        "·   [cyan]opencra kev refresh[/cyan]"
    )
    mark_first_run_done()
