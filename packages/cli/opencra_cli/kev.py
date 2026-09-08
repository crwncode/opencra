"""CISA KEV catalog download and local index."""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

import httpx
from opencra_shared.kev import KevEntry, index_kev_by_cve, parse_kev_catalog

from opencra_cli.db import Cache
from opencra_cli.httputil import client

logger = logging.getLogger("opencra.kev")

KEV_URL = "https://github.com/cisagov/kev-data/raw/main/known_exploited_vulnerabilities.json"
KEV_TTL = timedelta(hours=24)


class KevError(Exception):
    def __init__(self, message: str) -> None:
        super().__init__(message)


def refresh(cache: Cache) -> tuple[int, datetime]:
    try:
        with client() as http:
            response = http.get(KEV_URL)
            response.raise_for_status()
            payload = response.json()
    except httpx.HTTPError as exc:
        raise KevError(f"Failed to download CISA KEV catalog: {exc}") from exc
    if not isinstance(payload, dict) or "vulnerabilities" not in payload:
        raise KevError("KEV catalog JSON is missing a vulnerabilities array.")
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
