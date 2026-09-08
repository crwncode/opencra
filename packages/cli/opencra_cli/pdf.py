"""Community PDF export with WeasyPrint, falling back to HTML/Markdown."""

from __future__ import annotations

from pathlib import Path

from jinja2 import Template
from opencra_shared.models import ScanResult

from opencra_cli.render import DISCLAIMER

_HTML_TEMPLATE = Template(
    """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <title>OpenCRA scan report</title>
  <style>
    body { font-family: Helvetica, Arial, sans-serif; margin: 32px; color: #111; }
    h1 { font-size: 20px; }
    .disclaimer { background: #fff6e5; border: 1px solid #e6c36a; padding: 12px; }
    table { border-collapse: collapse; width: 100%; margin-top: 16px; font-size: 12px; }
    th, td { border: 1px solid #ccc; padding: 6px 8px; text-align: left; }
    th { background: #f4f4f4; }
    .kev { color: #b00020; font-weight: bold; }
  </style>
</head>
<body>
  <h1>OpenCRA community scan report</h1>
  <p>Target: {{ result.target }}<br/>Scanned: {{ result.scanned_at }}</p>
  <p class="disclaimer">{{ disclaimer }}</p>
  <p>Components: {{ result.sbom.components|length }} ·
     Matches: {{ result.matches|length }} ·
     KEV hits: {{ result.kev_hits|length }}</p>
  <table>
    <thead>
      <tr><th>Package</th><th>Version</th><th>ID</th><th>Severity</th><th>KEV</th></tr>
    </thead>
    <tbody>
    {% for m in result.matches %}
      <tr>
        <td>{{ m.component_name or m.purl }}</td>
        <td>{{ m.component_version or "" }}</td>
        <td>{{ m.cve_id or m.osv_id or "" }}</td>
        <td>{{ m.severity or "" }}</td>
        <td class="{{ 'kev' if m.in_kev else '' }}">{{ "KEV" if m.in_kev else "" }}</td>
      </tr>
    {% endfor %}
    </tbody>
  </table>
</body>
</html>
""".strip()
)

PDF_HINT = (
    "WeasyPrint needs Cairo and Pango. Install them, or use the HTML/Markdown fallback:\n"
    "  macOS:  brew install cairo pango\n"
    "  Debian: sudo apt install libcairo2 libpango-1.0-0 libgdk-pixbuf-2.0-0 "
    "libffi-dev shared-mime-info"
)


def weasyprint_status() -> tuple[bool, str]:
    try:
        import weasyprint  # noqa: F401
    except ImportError:
        return False, "weasyprint is not installed (pip install 'opencra-cli[pdf]')"
    try:
        from weasyprint import HTML  # noqa: F401
    except Exception as exc:  # native cairo/pango missing
        return False, f"WeasyPrint native libraries missing: {exc}\n{PDF_HINT}"
    return True, "WeasyPrint available"


def render_html(result: ScanResult) -> str:
    return _HTML_TEMPLATE.render(result=result, disclaimer=DISCLAIMER)


def render_markdown(result: ScanResult) -> str:
    lines = [
        "# OpenCRA community scan report",
        "",
        f"Target: `{result.target}`",
        f"Scanned: {result.scanned_at}",
        "",
        f"> {DISCLAIMER}",
        "",
        f"Components: {len(result.sbom.components)} · "
        f"Matches: {len(result.matches)} · KEV hits: {len(result.kev_hits)}",
        "",
        "| Package | Version | ID | Severity | KEV |",
        "|---|---|---|---|---|",
    ]
    for match in result.matches:
        lines.append(
            f"| {match.component_name or match.purl} | {match.component_version or ''} | "
            f"{match.cve_id or match.osv_id or ''} | {match.severity or ''} | "
            f"{'KEV' if match.in_kev else ''} |"
        )
    return "\n".join(lines) + "\n"


def export_report(result: ScanResult, path: Path) -> Path:
    """Write PDF if possible; otherwise write HTML (and Markdown alongside)."""
    html = render_html(result)
    ok, reason = weasyprint_status()
    suffix = path.suffix.lower()
    if ok and suffix in {"", ".pdf"}:
        from weasyprint import HTML

        dest = path if suffix == ".pdf" else path.with_suffix(".pdf")
        HTML(string=html).write_pdf(dest)
        return dest

    html_path = path.with_suffix(".html") if suffix == ".pdf" else path
    if html_path.suffix.lower() != ".html":
        html_path = path.with_suffix(".html")
    html_path.write_text(html, encoding="utf-8")
    md_path = html_path.with_suffix(".md")
    md_path.write_text(render_markdown(result), encoding="utf-8")
    # Surface the reason to the caller via a sidecar note.
    html_path.with_suffix(".pdf-fallback.txt").write_text(reason + "\n", encoding="utf-8")
    return html_path
