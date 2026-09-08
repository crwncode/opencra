"""OpenCRA Typer CLI."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path

import typer
from opencra_shared.models import FailOn, OutputFormat, ScanResult
from rich.console import Console

from opencra_cli import __version__
from opencra_cli.db import Cache, default_db_path
from opencra_cli.kev import KevError, load_index, refresh
from opencra_cli.match import merge_matches
from opencra_cli.nvd import cvss_from_nvd, enrich_cve
from opencra_cli.osv import ping as osv_ping
from opencra_cli.osv import query_batch
from opencra_cli.pdf import PDF_HINT, export_report, weasyprint_status
from opencra_cli.render import format_payload, print_table, result_to_json, write_output
from opencra_cli.syft import SyftError, resolve_syft, scan_to_document, syft_version, version_ok
from opencra_cli.sync import ingest

app = typer.Typer(
    name="opencra",
    help="CRA Article 14 reporting readiness for your SBOM. A KEV hit is a candidate, not awareness.",
    no_args_is_help=True,
)
console = Console()
err_console = Console(stderr=True)


class FailOnOpt(str, Enum):
    none = "none"
    kev = "kev"
    critical = "critical"
    high = "high"


class FormatOpt(str, Enum):
    table = "table"
    json = "json"
    cyclonedx = "cyclonedx"
    spdx = "spdx"


class EnrichOpt(str, Enum):
    none = "none"
    nvd = "nvd"


def _configure_logging(verbose: bool, quiet: bool) -> None:
    level = logging.WARNING
    if verbose:
        level = logging.DEBUG
    if quiet:
        level = logging.ERROR
    logging.basicConfig(level=level, format="%(levelname)s %(name)s: %(message)s")


def _exit(code: int, message: str | None = None) -> None:
    if message:
        err_console.print(f"[red]{message}[/red]")
    raise typer.Exit(code)


def _run_scan(
    target: str,
    *,
    offline: bool,
    enrich: EnrichOpt,
    syft_bin: str | None,
    cache: Cache,
) -> ScanResult:
    document = scan_to_document(target, syft_bin=syft_bin)
    skipped = [c for c in document.components if not c.purl]
    valid_purls = sorted({c.purl for c in document.components if c.purl})
    warnings: list[str] = []
    if skipped:
        warnings.append(
            f"Skipped {len(skipped)} component(s) with invalid or missing PURLs "
            "(they were not sent to OSV)."
        )

    kev_index = load_index(cache, offline=offline)
    osv_by_purl = query_batch(valid_purls, cache, offline=offline)
    matches = merge_matches(document.components, osv_by_purl, kev_index)

    if enrich is EnrichOpt.nvd and not offline:
        for match in matches:
            if match.cve_id and match.cvss_v3 is None:
                payload = enrich_cve(match.cve_id)
                if payload:
                    match.cvss_v3 = cvss_from_nvd(payload)

    return ScanResult(
        target=target,
        scanned_at=datetime.now(timezone.utc),
        sbom=document,
        matches=matches,
        skipped_components=skipped,
        offline=offline,
        warnings=warnings,
    )


@app.command()
def scan(
    target: str = typer.Argument(".", help="Path, image, or Syft target to scan."),
    format: FormatOpt = typer.Option(FormatOpt.table, "--format", help="Output format."),
    output: Path | None = typer.Option(None, "--output", help="Write formatted output to PATH."),
    export_pdf: Path | None = typer.Option(
        None, "--export-pdf", help="Write a community PDF (falls back to HTML/Markdown)."
    ),
    fail_on: FailOnOpt = typer.Option(FailOnOpt.none, "--fail-on"),
    offline: bool = typer.Option(False, "--offline", help="Use SQLite caches only. No network."),
    enrich: EnrichOpt = typer.Option(EnrichOpt.none, "--enrich"),
    sync_cloud: bool = typer.Option(False, "--sync-cloud", help="POST results to CRA-Shield."),
    syft_bin: str | None = typer.Option(None, "--syft-bin", help="Path to the Syft binary."),
    quiet: bool = typer.Option(False, "--quiet"),
    verbose: bool = typer.Option(False, "--verbose"),
) -> None:
    """Generate an SBOM with Syft and match components against OSV + CISA KEV."""
    _configure_logging(verbose, quiet)
    try:
        with Cache() as cache:
            result = _run_scan(
                target,
                offline=offline,
                enrich=enrich,
                syft_bin=syft_bin,
                cache=cache,
            )
            cache.save_scan(target, result_to_json(result), result.sbom.model_dump(mode="json"))
    except SyftError as exc:
        _exit(exc.exit_code, str(exc))
    except KevError as exc:
        _exit(2, str(exc))

    fmt = OutputFormat(format.value)
    if fmt is OutputFormat.TABLE and not quiet:
        print_table(result, console)
    elif fmt is not OutputFormat.TABLE:
        payload = format_payload(result, fmt)
        if output:
            write_output(result, fmt, output)
            if not quiet:
                console.print(f"Wrote {fmt.value} to {output}")
        else:
            console.print(payload)
    elif output:
        write_output(result, OutputFormat.JSON, output)

    if export_pdf:
        written = export_report(result, export_pdf)
        if not quiet:
            if written.suffix == ".pdf":
                console.print(f"Wrote PDF to {written}")
            else:
                console.print(
                    f"[yellow]PDF engine unavailable.[/yellow] Wrote {written} instead.\n{PDF_HINT}"
                )

    if sync_cloud:
        response = ingest(result)
        if not quiet:
            console.print(response.get("message") or response)

    threshold = FailOn(fail_on.value)
    if result.fails(threshold):
        _exit(1, f"Scan failed --fail-on {threshold.value}.")


@app.command()
def doctor(
    syft_bin: str | None = typer.Option(None, "--syft-bin"),
) -> None:
    """Check Syft, network, cache, and PDF engine. Friendly, not a stack trace."""
    console.print(f"[bold]OpenCRA[/bold] {__version__}")
    try:
        path = resolve_syft(syft_bin)
        label, parsed = syft_version(syft_bin)
        ok = version_ok(parsed)
        status = "[green]ok[/green]" if ok else "[yellow]old[/yellow]"
        console.print(f"Syft: {status} {path} ({label})")
        if not ok:
            console.print("  Install Syft >= 1.0.0 for CycloneDX 1.6 output.")
    except SyftError as exc:
        console.print(f"Syft: [red]missing[/red]\n{exc}")

    cache_path = default_db_path()
    console.print(f"Cache: {cache_path} ({'exists' if cache_path.exists() else 'will be created'})")
    with Cache() as cache:
        fetched = cache.get_kev_fetched_at()
        console.print(f"KEV cache: {fetched.isoformat() if fetched else 'empty'}")

    console.print(f"OSV: {'reachable' if osv_ping() else 'unreachable (offline scans still work)'}")
    pdf_ok, pdf_reason = weasyprint_status()
    console.print(f"PDF engine: {'ok' if pdf_ok else 'fallback'} — {pdf_reason}")
    console.print(
        "[dim]A KEV match is a CRA candidate. Clocks start only after human awareness.[/dim]"
    )


@app.command("kev")
def kev_cmd(
    action: str = typer.Argument("refresh", help="Only 'refresh' is supported."),
) -> None:
    """Download or refresh the CISA KEV catalog into the local cache."""
    if action != "refresh":
        _exit(2, "Usage: opencra kev refresh")
    try:
        with Cache() as cache:
            count, fetched = refresh(cache)
    except KevError as exc:
        _exit(2, str(exc))
    console.print(f"Cached {count} CISA KEV entries ({fetched.isoformat()}).")


@app.command()
def report(
    last: bool = typer.Option(False, "--last", help="Re-render the most recent local scan."),
    export_pdf: Path | None = typer.Option(None, "--export-pdf"),
    format: FormatOpt = typer.Option(FormatOpt.table, "--format"),
) -> None:
    """Show the last cached scan without invoking Syft."""
    if not last:
        _exit(2, "Pass --last to print the most recent scan.")
    with Cache() as cache:
        raw = cache.last_scan()
    if raw is None:
        _exit(2, "No cached scans. Run `opencra scan .` first.")
    result = ScanResult.model_validate(raw)
    fmt = OutputFormat(format.value)
    if fmt is OutputFormat.TABLE:
        print_table(result, console)
    else:
        console.print(format_payload(result, fmt))
    if export_pdf:
        written = export_report(result, export_pdf)
        console.print(f"Wrote report to {written}")


@app.callback()
def main() -> None:
    """OpenCRA CLI."""
    return


if __name__ == "__main__":
    app()
