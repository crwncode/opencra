"""Merge OSV results with the CISA KEV index into VulnMatch rows."""

from __future__ import annotations

from typing import Any

from opencra_shared.kev import KevEntry, extract_cves
from opencra_shared.models import Component, VulnMatch


def _severity(vuln: dict[str, Any]) -> tuple[str | None, float | None]:
    severity = None
    score = None
    for item in vuln.get("severity") or []:
        if not isinstance(item, dict):
            continue
        typ = str(item.get("type") or "").upper()
        raw = item.get("score")
        if typ.startswith("CVSS") and raw is not None:
            try:
                # CVSS vector or numeric
                if isinstance(raw, int | float):
                    score = float(raw)
                else:
                    text = str(raw)
                    if text.replace(".", "", 1).isdigit():
                        score = float(text)
            except ValueError:
                pass
    db = vuln.get("database_specific") or {}
    sev = db.get("severity")
    if isinstance(sev, str):
        severity = sev.upper()
    if score is not None and severity is None:
        if score >= 9.0:
            severity = "CRITICAL"
        elif score >= 7.0:
            severity = "HIGH"
        elif score >= 4.0:
            severity = "MEDIUM"
        else:
            severity = "LOW"
    return severity, score


def merge_matches(
    components: list[Component],
    osv_by_purl: dict[str, list[dict[str, Any]]],
    kev_index: dict[str, KevEntry],
) -> list[VulnMatch]:
    matches: list[VulnMatch] = []
    seen: set[tuple[str, str]] = set()
    for component in components:
        if not component.purl:
            continue
        for vuln in osv_by_purl.get(component.purl, []):
            osv_id = str(vuln.get("id") or "")
            aliases = [str(a) for a in (vuln.get("aliases") or [])]
            cves = extract_cves(aliases, osv_id)
            cve_id = cves[0] if cves else None
            key = (component.purl, osv_id or cve_id or "")
            if key in seen:
                continue
            seen.add(key)
            kev = None
            for cve in cves:
                if cve in kev_index:
                    kev = kev_index[cve]
                    cve_id = cve
                    break
            severity, score = _severity(vuln)
            matches.append(
                VulnMatch(
                    purl=component.purl,
                    component_name=component.name,
                    component_version=component.version,
                    osv_id=osv_id or None,
                    cve_id=cve_id,
                    severity=severity,
                    cvss_v3=score,
                    in_kev=kev is not None,
                    kev_added_at=kev.date_added if kev else None,
                    kev_ransomware=kev.known_ransomware if kev else None,
                    aliases=aliases,
                    summary=vuln.get("summary"),
                )
            )
    return matches
