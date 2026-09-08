"""OSV Query Batch client with 100-item chunks and SQLite cache."""

from __future__ import annotations

import logging
from typing import Any

import httpx

from opencra_cli.db import Cache
from opencra_cli.httputil import USER_AGENT, client

logger = logging.getLogger("opencra.osv")

OSV_QUERYBATCH = "https://api.osv.dev/v1/querybatch"
BATCH_SIZE = 100


def _chunks(items: list[str], size: int) -> list[list[str]]:
    return [items[i : i + size] for i in range(0, len(items), size)]


def query_batch(
    purls: list[str],
    cache: Cache,
    *,
    offline: bool = False,
) -> dict[str, list[dict[str, Any]]]:
    """Return {purl: [osv vuln dicts]} for validated PURLs only."""
    results: dict[str, list[dict[str, Any]]] = {}
    missing: list[str] = []
    for purl in purls:
        cached = cache.get_osv(purl)
        if cached is not None:
            results[purl] = cached
        else:
            missing.append(purl)

    if not missing:
        return results
    if offline:
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
            cache.save_osv(purl, vulns)
            results[purl] = vulns
        # If OSV returned fewer results than queries, mark leftovers empty.
        if len(results_list) < len(chunk):
            for purl in chunk[len(results_list) :]:
                cache.save_osv(purl, [])
                results[purl] = []
    return results


def ping() -> bool:
    try:
        with client() as http:
            response = http.get("https://api.osv.dev/v1/querybatch", headers={"User-Agent": USER_AGENT})
            return response.status_code in {200, 405, 415}
    except httpx.HTTPError:
        return False
