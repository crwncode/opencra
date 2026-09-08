"""Rich table and file exporters."""

from __future__ import annotations

import json
from pathlib import Path

from opencra_shared.models import OutputFormat, ScanResult
from opencra_shared.sbom import cyclonedx_to_spdx, serialize_cyclonedx
from rich.console import Console
from rich.table import Table

DISCLAIMER = (
    "OpenCRA prepares evidence. A KEV match is a CRA candidate, not legal awareness. "
    "Article 14 clocks start only after a human assessment."
)


def result_to_json(result: ScanResult) -> dict:
    return result.model_dump(mode="json")


def format_payload(result: ScanResult, fmt: OutputFormat) -> str:
    if fmt is OutputFormat.JSON:
        return json.dumps(result_to_json(result), indent=2)
    if fmt is OutputFormat.CYCLONEDX:
        return json.dumps(serialize_cyclonedx(result.sbom), indent=2)
    if fmt is OutputFormat.SPDX:
        return json.dumps(cyclonedx_to_spdx(result.sbom), indent=2)
    return ""


def write_output(result: ScanResult, fmt: OutputFormat, path: Path) -> None:
    path.write_text(format_payload(result, fmt), encoding="utf-8")


def print_table(result: ScanResult, console: Console) -> None:
    console.print(f"[bold]OpenCRA[/bold] scan of [cyan]{result.target}[/cyan]")
    console.print(f"[dim]{DISCLAIMER}[/dim]")
    if result.warnings:
        for warning in result.warnings:
            console.print(f"[yellow]warn[/yellow] {warning}")

    kev_count = len(result.kev_hits)
    console.print(
        f"Components: {len(result.sbom.components)}  "
        f"Matches: {len(result.matches)}  "
        f"[red]KEV hits: {kev_count}[/red]"
        if kev_count
        else f"Components: {len(result.sbom.components)}  Matches: {len(result.matches)}  KEV hits: 0"
    )

    table = Table(show_header=True, header_style="bold")
    table.add_column("Package")
    table.add_column("Version")
    table.add_column("ID")
    table.add_column("Severity")
    table.add_column("KEV")
    table.add_column("Action")

    rows = sorted(result.matches, key=lambda m: (not m.in_kev, m.severity or "ZZ", m.purl))
    if not rows:
        console.print("[green]No vulnerability matches.[/green]")
        return

    for match in rows:
        kev = "[bold red]KEV[/bold red]" if match.in_kev else ""
        action = (
            "Candidate — assess awareness (do not auto-file)"
            if match.in_kev
            else "Triage"
        )
        ident = match.cve_id or match.osv_id or "—"
        table.add_row(
            match.component_name or match.purl,
            match.component_version or "—",
            ident,
            match.severity or "—",
            kev,
            action,
        )
    console.print(table)
    if kev_count:
        console.print(
            "[bold]KEV hits are CRA candidates.[/bold] "
            "Acknowledge awareness in CRA-Shield to start the 24-hour clock."
        )
