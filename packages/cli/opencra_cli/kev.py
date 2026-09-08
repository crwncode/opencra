"""CISA KEV catalog download and local index."""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx
from opencra_shared.kev import KevEntry, index_kev_by_cve, parse_kev_catalog

from opencra_cli.db import Cache
from opencra_cli.httputil import client

logger = logging.getLogger("opencra.kev")

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_FALLBACK_URL = (
    "https://raw.githubusercontent.com/cisagov/known-exploited-vulnerabilities-data/"
    "main/known_exploited_vulnerabilities.json"
)
KEV_SOURCES = (KEV_URL, KEV_FALLBACK_URL)
KEV_TTL = timedelta(hours=24)


class KevError(Exception):
    def __init__(self, message: str) -> None:
        super().__init__(message)


def _fetch_kev_payload(http: httpx.Client, url: str) -> dict[str, Any]:
    response = http.get(url)
    response.raise_for_status()
    payload = response.json()
    if not isinstance(payload, dict) or "vulnerabilities" not in payload:
        raise KevError("KEV catalog JSON is missing a vulnerabilities array.")
    return payload


def refresh(cache: Cache) -> tuple[int, datetime]:
    last_error: Exception | None = None
    payload: dict[str, Any] | None = None
    with client() as http:
        for url in KEV_SOURCES:
            try:
                payload = _fetch_kev_payload(http, url)
                logger.info("Downloaded CISA KEV catalog from %s", url)
                break
            except (httpx.HTTPError, ValueError, KevError) as exc:
                last_error = exc
                logger.warning("KEV download failed from %s: %s", url, exc)
    if payload is None:
        raise KevError(f"Failed to download CISA KEV catalog: {last_error}") from last_error
    cache.save_kev_catalog(payload)
    entries = parse_kev_catalog(payload)
    fetched = cache.get_kev_fetched_at() or datetime.now(timezone.utc)
    return len(entries), fetched


def load_index(cache: Cache, *, offline: bool = False, force_refresh: bool = False) -> dict[str, KevEntry]:
    fetched = cache.get_kev_fetched_at()
    stale = fetched is None or datetime.now(timezone.utc) - fetched > KEV_TTL
    if (stale or force_refresh) and not offline:
        try:
            refresh(cache)
        except KevError as exc:
            if cache.get_kev_catalog() is None:
                raise
            logger.warning("KEV refresh failed, using cached catalog: %s", exc)
    payload = cache.get_kev_catalog()
    if payload is None:
        if offline:
            raise KevError(
                "No cached CISA KEV catalog. Re-run without --offline after "
                "`opencra kev refresh` while online."
            )
        raise KevError("CISA KEV catalog is unavailable.")
    return index_kev_by_cve(parse_kev_catalog(payload))
