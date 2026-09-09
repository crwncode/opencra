"""OSV Query Batch client with 100-item chunks and SQLite cache."""

from __future__ import annotations

import logging
from typing import Any

import httpx
from opencra_shared.kev import extract_cves

from opencra_cli.db import Cache
from opencra_cli.httputil import USER_AGENT, client

logger = logging.getLogger("opencra.osv")

OSV_QUERYBATCH = "https://api.osv.dev/v1/querybatch"
OSV_VULN = "https://api.osv.dev/v1/vulns"
BATCH_SIZE = 100
_HYDRATE_KEYS = ("aliases", "summary", "severity", "database_specific")


def _chunks(items: list[str], size: int) -> list[list[str]]:
    return [items[i : i + size] for i in range(0, len(items), size)]


def _vuln_id(vuln: dict[str, Any]) -> str:
    return str(vuln.get("id") or "")


def _has_cve(vuln: dict[str, Any]) -> bool:
    aliases = [str(a) for a in (vuln.get("aliases") or [])]
    return bool(extract_cves(aliases, _vuln_id(vuln)))


def _merge_detail(vuln: dict[str, Any], detail: dict[str, Any]) -> dict[str, Any]:
    merged = dict(vuln)
    for key in _HYDRATE_KEYS:
        if key in detail and not merged.get(key):
            merged[key] = detail[key]
    return merged


def hydrate_vulns(
    vulns: list[dict[str, Any]],
    cache: Cache,
    *,
    offline: bool = False,
) -> list[dict[str, Any]]:
    """Fill aliases (and related fields) so KEV can match CVE-IDs.

    OSV ``querybatch`` returns ``{id, modified}`` stubs. Full records come from
    ``GET /v1/vulns/{id}``. Offline mode never opens HTTP.
    """
    if offline or not vulns:
        return vulns

    to_fetch: list[str] = []
    for vuln in vulns:
        if not isinstance(vuln, dict) or _has_cve(vuln):
            continue
        vid = _vuln_id(vuln)
        if vid and cache.get_osv_vuln(vid) is None:
            to_fetch.append(vid)

    if to_fetch:
        with client() as http:
            for vid in dict.fromkeys(to_fetch):
                try:
                    response = http.get(f"{OSV_VULN}/{vid}")
                    response.raise_for_status()
                    body = response.json()
                except httpx.HTTPError as exc:
                    logger.warning("OSV vuln %s fetch failed: %s", vid, exc)
                    continue
                if isinstance(body, dict):
                    cache.save_osv_vuln(vid, body)

    hydrated: list[dict[str, Any]] = []
    for vuln in vulns:
        if not isinstance(vuln, dict):
            continue
        if _has_cve(vuln):
            hydrated.append(vuln)
            continue
        vid = _vuln_id(vuln)
        detail = cache.get_osv_vuln(vid) if vid else None
        hydrated.append(_merge_detail(vuln, detail) if detail else vuln)
    return hydrated


def query_batch(
    purls: list[str],
    cache: Cache,
    *,
    offline: bool = False,
) -> dict[str, list[dict[str, Any]]]:
    """Return {purl: [osv vuln dicts]} for validated PURLs only."""
    results: dict[str, list[dict[str, Any]]] = {}
    missing: list[str] = []
    persist: set[str] = set()
    for purl in purls:
        cached = cache.get_osv(purl)
        if cached is not None:
            results[purl] = cached
            persist.add(purl)
        else:
            missing.append(purl)

    if offline:
        if missing:
            logger.warning("Offline mode: %s PURLs have no cached OSV data", len(missing))
            for purl in missing:
                results[purl] = []
        return results

    for chunk in _chunks(missing, BATCH_SIZE):
        payload = {"queries": [{"package": {"purl": purl}} for purl in chunk]}
        try:
            with client() as http:
                response = http.post(OSV_QUERYBATCH, json=payload)
                response.raise_for_status()
                body = response.json()
        except httpx.HTTPError as exc:
            logger.warning("OSV querybatch failed for %s items: %s", len(chunk), exc)
            for purl in chunk:
                results.setdefault(purl, [])
            continue

        results_list = body.get("results") or []
        for purl, item in zip(chunk, results_list, strict=False):
            vulns = item.get("vulns") or [] if isinstance(item, dict) else []
            results[purl] = vulns if isinstance(vulns, list) else []
            persist.add(purl)
        if len(results_list) < len(chunk):
            for purl in chunk[len(results_list) :]:
                results[purl] = []
                persist.add(purl)

    for purl, vulns in list(results.items()):
        hydrated = hydrate_vulns(vulns, cache, offline=False)
        results[purl] = hydrated
        if purl in persist:
            cache.save_osv(purl, hydrated)
    return results


def ping() -> bool:
    try:
        with client() as http:
            response = http.get("https://api.osv.dev/v1/querybatch", headers={"User-Agent": USER_AGENT})
            return response.status_code in {200, 405, 415}
    except httpx.HTTPError:
        return False
