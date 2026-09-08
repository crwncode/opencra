"""Map a CRA case + product + org to ENISA SRP form fields and CSIRT Markdown."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape
from opencra_shared.clocks import CaseType, compute_clocks

from opencra_api.orm import CraCase, Organization, Product
from opencra_api.srp.adapter import SrpSubmission

TEMPLATE_DIR = Path(__file__).parent / "templates"

_CSIRT_TEMPLATES = {
    "DE": "de_bsi.md.j2",
    "FR": "fr_anssi.md.j2",
    "NL": "nl_ncsc.md.j2",
    "IE": "ie_ncsc.md.j2",
    "DEFAULT": "default.md.j2",
}


def _env() -> Environment:
    return Environment(
        loader=FileSystemLoader(str(TEMPLATE_DIR)),
        autoescape=select_autoescape(enabled_extensions=("html",)),
        trim_blocks=True,
        lstrip_blocks=True,
    )


def map_fields(org: Organization, product: Product, case: CraCase, stage: str) -> dict:
    clocks = compute_clocks(
        CaseType(case.case_type),
        awareness_at=case.awareness_at,
        fix_available_at=case.fix_available_at,
        notification_submitted_at=case.notification_submitted_at,
        early_warning_submitted=case.early_warning_submitted_at is not None,
        notification_submitted=case.notification_submitted_at is not None,
        final_submitted=case.final_submitted_at is not None,
    )
    return {
        "stage": stage,
        "manufacturer_name": org.name,
        "main_establishment_member_state": org.main_establishment_ms or "",
        "designated_csirt": org.designated_csirt or "",
        "product_name": product.name,
        "product_version": product.version or "",
        "market_member_states": ", ".join(product.market_member_states or []),
        "case_type": case.case_type,
        "awareness_at": case.awareness_at.isoformat() if case.awareness_at else "",
        "early_warning_due_at": (
            clocks.early_warning_due_at.isoformat() if clocks.early_warning_due_at else ""
        ),
        "notification_due_at": (
            clocks.notification_due_at.isoformat() if clocks.notification_due_at else ""
        ),
        "final_report_due_at": (
            clocks.final_report_due_at.isoformat() if clocks.final_report_due_at else ""
        ),
        "exploit_nature": case.exploit_nature or "",
        "sensitivity": case.sensitivity or "",
        "corrective_measures": case.corrective_measures or "",
        "srp_reference_id": case.srp_reference_id or "",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "disclaimer": (
            "This packet is a drafting aid. It does not file with ENISA. "
            "A human must submit through the Single Reporting Platform portal."
        ),
    }


def render_markdown(org: Organization, product: Product, case: CraCase, stage: str) -> str:
    fields = map_fields(org, product, case, stage)
    ms = (org.main_establishment_ms or "DEFAULT").upper()
    name = _CSIRT_TEMPLATES.get(ms, _CSIRT_TEMPLATES["DEFAULT"])
    template = _env().get_template(name)
    return template.render(**fields, fields=fields)


def build_packet(org: Organization, product: Product, case: CraCase, stage: str) -> SrpSubmission:
    fields = map_fields(org, product, case, stage)
    return SrpSubmission(stage=stage, fields=fields, markdown=render_markdown(org, product, case, stage))
