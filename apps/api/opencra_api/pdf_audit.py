"""Formal CRA audit PDF — Pro+ gated."""

from __future__ import annotations

from jinja2 import Template

from opencra_api.orm import AuditEvent, CraCase, Organization, Product, Sbom, VulnMatchRow

_TEMPLATE = Template(
    """
<!DOCTYPE html>
<html><head><meta charset="utf-8"/><title>CRA Audit Report</title>
<style>
body{font-family:Georgia,serif;margin:36px;color:#111}
h1{font-size:22px} table{border-collapse:collapse;width:100%;font-size:12px}
td,th{border:1px solid #ccc;padding:6px} .note{background:#fff6e5;padding:10px}
</style></head><body>
<h1>OpenCRA audit report</h1>
<p class="note">This report is evidence for a compliance officer. It does not certify
CE marking or file with ENISA. Clocks start only from human awareness_at.</p>
<p>Organization: {{ org.name }} ({{ org.main_establishment_ms }})<br/>
Product: {{ product.name }} {{ product.version }}<br/>
SBOM serials: {{ serials }}</p>
<h2>KEV matches</h2>
<table><tr><th>PURL</th><th>CVE</th><th>KEV</th><th>Status</th></tr>
{% for m in matches %}
<tr><td>{{ m.purl }}</td><td>{{ m.cve_id }}</td><td>{{ m.in_kev }}</td><td>{{ m.status }}</td></tr>
{% endfor %}
</table>
<h2>Case timeline</h2>
<table><tr><th>Case</th><th>Status</th><th>Awareness</th><th>Fix</th></tr>
{% for c in cases %}
<tr><td>{{ c.id }}</td><td>{{ c.status }}</td><td>{{ c.awareness_at }}</td><td>{{ c.fix_available_at }}</td></tr>
{% endfor %}
</table>
<h2>Audit hash chain (excerpt)</h2>
<table><tr><th>Time</th><th>Action</th><th>Hash</th></tr>
{% for e in events %}
<tr><td>{{ e.created_at }}</td><td>{{ e.action }}</td><td>{{ e.event_hash[:16] }}…</td></tr>
{% endfor %}
</table>
</body></html>
""".strip()
)


def render_audit_html(
    org: Organization,
    product: Product,
    sboms: list[Sbom],
    matches: list[VulnMatchRow],
    cases: list[CraCase],
    events: list[AuditEvent],
) -> str:
    serials = ", ".join(s.serial_number or s.id for s in sboms) or "none"
    return _TEMPLATE.render(
        org=org,
        product=product,
        serials=serials,
        matches=matches,
        cases=cases,
        events=events,
    )


def render_audit_pdf_or_html(
    org: Organization,
    product: Product,
    sboms: list[Sbom],
    matches: list[VulnMatchRow],
    cases: list[CraCase],
    events: list[AuditEvent],
) -> tuple[bytes, str]:
    html = render_audit_html(org, product, sboms, matches, cases, events)
    try:
        from weasyprint import HTML

        return HTML(string=html).write_pdf(), "application/pdf"
    except Exception:
        return html.encode(), "text/html"
