from __future__ import annotations

from io import StringIO
from pathlib import Path

import pytest
from opencra_cli.app import app
from opencra_cli.db import Cache
from opencra_cli.guide import (
    USAGE_EPILOG,
    first_run_pending,
    mark_first_run_done,
    maybe_print_first_run,
    print_post_syft_install_tip,
)
from opencra_cli.paths import FIRST_RUN_MARKER, first_run_marker_path
from rich.console import Console
from typer.testing import CliRunner

SAMPLE_CDX = Path(__file__).resolve().parents[1] / "examples" / "sample.cdx.json"


def _isolate_home(monkeypatch: pytest.MonkeyPatch, home: Path) -> None:
    monkeypatch.setenv("OPENCRA_HOME", str(home))
    monkeypatch.setenv("OPENCRA_CACHE", str(home / "cache.db"))


def _isolate_cli(monkeypatch: pytest.MonkeyPatch, home: Path) -> None:
    _isolate_home(monkeypatch, home)
    monkeypatch.setattr("opencra_cli.syft.which_syft", lambda: None)
    monkeypatch.setattr("opencra_cli.app.which_syft", lambda: None)
    monkeypatch.setattr("opencra_cli.app.osv_ping", lambda: False)


def test_first_run_marker_path_uses_opencra_home(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "state"
    _isolate_home(monkeypatch, home)
    assert first_run_marker_path() == home / FIRST_RUN_MARKER
    assert first_run_pending()
    mark_first_run_done()
    assert first_run_marker_path().is_file()
    assert not first_run_pending()


def test_maybe_print_first_run_once(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _isolate_home(monkeypatch, tmp_path / "home")
    buf = StringIO()
    console = Console(file=buf, force_terminal=True, color_system=None, width=100)
    assert maybe_print_first_run(console) is True
    first = buf.getvalue()
    assert "OpenCRA is ready." in first
    assert "opencra scan ." in first
    assert "opencra doctor" in first
    assert "opencra kev refresh" in first
    assert "opencra --help" in first
    assert first.count("OpenCRA is ready.") == 1
    assert first_run_marker_path().is_file()

    buf2 = StringIO()
    console2 = Console(file=buf2, force_terminal=True, color_system=None, width=100)
    assert maybe_print_first_run(console2) is False
    assert buf2.getvalue() == ""


def test_maybe_print_first_run_skips_quiet(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _isolate_home(monkeypatch, tmp_path / "home")
    buf = StringIO()
    console = Console(file=buf, force_terminal=True, color_system=None, width=100)
    assert maybe_print_first_run(console, quiet=True) is False
    assert buf.getvalue() == ""
    assert first_run_pending()


def test_print_post_syft_install_tip_writes_marker(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _isolate_home(monkeypatch, tmp_path / "home")
    buf = StringIO()
    console = Console(file=buf, force_terminal=True, color_system=None, width=100)
    dest = tmp_path / "home" / "bin" / "syft"
    print_post_syft_install_tip(console, dest)
    text = buf.getvalue()
    assert "Syft installed" in text
    assert str(dest) in text
    assert "opencra scan ." in text
    assert first_run_marker_path().is_file()


def test_cli_first_run_once_then_silent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    _isolate_cli(monkeypatch, home)
    runner = CliRunner()
    first = runner.invoke(app, ["doctor"])
    assert first.exit_code == 0, first.stdout + first.stderr
    combined = first.stdout + first.stderr
    assert "OpenCRA is ready." in combined
    assert "opencra kev refresh" in combined
    assert (home / FIRST_RUN_MARKER).is_file()

    second = runner.invoke(app, ["doctor"])
    assert second.exit_code == 0, second.stdout + second.stderr
    assert "OpenCRA is ready." not in (second.stdout + second.stderr)


def test_cli_first_run_suppressed_when_quiet(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    _isolate_cli(monkeypatch, home)
    with Cache(home / "cache.db") as cache:
        cache.save_kev_catalog({"vulnerabilities": []})

    result = CliRunner().invoke(app, ["scan", str(SAMPLE_CDX), "--offline", "--quiet"])
    assert result.exit_code == 0, result.stdout + result.stderr
    assert "OpenCRA is ready." not in (result.stdout + result.stderr)
    assert not (home / FIRST_RUN_MARKER).exists()


def test_help_includes_usage_epilog() -> None:
    result = CliRunner().invoke(app, ["--help"])
    assert result.exit_code == 0, result.stdout + result.stderr
    collapsed = " ".join(result.stdout.split())
    assert "opencra scan ." in collapsed
    assert "opencra doctor" in collapsed
    assert "opencra kev refresh" in collapsed
    assert "Try:" in collapsed
    assert USAGE_EPILOG.split("·")[0].strip().split()[-1] in collapsed
