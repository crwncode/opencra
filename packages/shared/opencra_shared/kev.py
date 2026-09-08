"""CISA Known Exploited Vulnerabilities catalog helpers."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel


class KevEntry(BaseModel):
    cve_id: str
    vendor: str | None = None
    product: str | None = None
    vulnerability_name: str | None = None
    date_added: datetime | None = None
    short_description: str | None = None
    required_action: str | None = None
    due_date: datetime | None = None
    known_ransomware: str | None = None
    notes: str | None = None


def _parse_date(value: Any) -> datetime | None:
    if not value or not isinstance(value, str):
        return None
    for fmt in ("%Y-%m-%d", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%SZ"):
        try:
            return datetime.strptime(value[:19] if "T" in value else value, fmt.replace("Z", ""))
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def parse_kev_catalog(payload: dict[str, Any]) -> list[KevEntry]:
    entries: list[KevEntry] = []
    for raw in payload.get("vulnerabilities") or []:
        if not isinstance(raw, dict):
            continue
        cve = raw.get("cveID") or raw.get("cve_id")
        if not cve:
            continue
        entries.append(
            KevEntry(
                cve_id=str(cve).upper(),
                vendor=raw.get("vendorProject"),
                product=raw.get("product"),
                vulnerability_name=raw.get("vulnerabilityName"),
                date_added=_parse_date(raw.get("dateAdded")),
                short_description=raw.get("shortDescription"),
                required_action=raw.get("requiredAction"),
                due_date=_parse_date(raw.get("dueDate")),
                known_ransomware=raw.get("knownRansomwareCampaignUse"),
                notes=raw.get("notes"),
            )
        )
    return entries


def index_kev_by_cve(entries: list[KevEntry]) -> dict[str, KevEntry]:
    return {entry.cve_id.upper(): entry for entry in entries}


def extract_cves(aliases: list[str], osv_id: str | None = None) -> list[str]:
    """Collect CVE-IDs from OSV aliases and the primary id."""
    found: list[str] = []
    for value in [*aliases, osv_id or ""]:
        upper = value.upper()
        if upper.startswith("CVE-") and upper not in found:
            found.append(upper)
    return found
