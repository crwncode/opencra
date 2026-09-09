"""Optional cloud ingest. Never required for local scans. No default host."""

from __future__ import annotations

import os
from typing import Any

import httpx
from opencra_shared.models import ScanResult

from opencra_cli.httputil import client


def ingest(
    result: ScanResult,
    *,
    api_url: str | None = None,
    api_key: str | None = None,
) -> dict[str, Any]:
    key = api_key or os.environ.get("OPENCRA_API_KEY")
    raw_base = api_url if api_url is not None else os.environ.get("OPENCRA_API_URL")
    base = (raw_base or "").rstrip("/")
    if not key or not base:
        return {
            "ok": False,
            "skipped": True,
            "message": (
                "Cloud sync skipped. Set OPENCRA_API_URL and OPENCRA_API_KEY to POST "
                "results to your own ingest endpoint. Local scan is complete."
            ),
        }
    payload = result.model_dump(mode="json")
    try:
        with client() as http:
            response = http.post(
                f"{base}/v1/ingest",
                json=payload,
                headers={"Authorization": f"Bearer {key}"},
            )
            response.raise_for_status()
            return {"ok": True, "response": response.json()}
    except httpx.HTTPError as exc:
        return {"ok": False, "message": f"Cloud ingest failed: {exc}"}
