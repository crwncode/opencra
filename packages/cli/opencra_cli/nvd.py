"""Optional NVD 2.0 enrichment. Off by default to avoid rate limits."""

from __future__ import annotations

import logging
import os
from typing import Any

import httpx

from opencra_cli.httputil import client

logger = logging.getLogger("opencra.nvd")

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def enrich_cve(cve_id: str) -> dict[str, Any] | None:
    headers: dict[str, str] = {}
    api_key = os.environ.get("NVD_API_KEY")
    if api_key:
        headers["apiKey"] = api_key
    try:
        with client(headers=headers) as http:
            response = http.get(NVD_URL, params={"cveId": cve_id})
            response.raise_for_status()
            return response.json()
    except httpx.HTTPError as exc:
        logger.warning("NVD lookup failed for %s: %s", cve_id, exc)
        return None


def cvss_from_nvd(payload: dict[str, Any]) -> float | None:
    try:
        vuln = payload["vulnerabilities"][0]["cve"]
        metrics = vuln.get("metrics") or {}
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            items = metrics.get(key)
            if items:
                return float(items[0]["cvssData"]["baseScore"])
    except (KeyError, IndexError, TypeError, ValueError):
        return None
    return None
