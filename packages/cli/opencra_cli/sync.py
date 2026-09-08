"""Optional CRA-Shield cloud ingest. Never required for local scans."""

from __future__ import annotations

import os
from typing import Any

import httpx
from opencra_shared.models import ScanResult

from opencra_cli.httputil import client

DEFAULT_API = "https://api.crashield.dev"
SIGNUP_URL = "https://crashield.dev/signup"


def ingest(
    result: ScanResult,
    *,
    api_url: str | None = None,
    api_key: str | None = None,
) -> dict[str, Any]:
    key = api_key or os.environ.get("OPENCRA_API_KEY")
    base = (api_url or os.environ.get("OPENCRA_API_URL") or DEFAULT_API).rstrip("/")
    if not key:
        return {
            "ok": False,
            "skipped": True,
            "message": (
                "No OPENCRA_API_KEY set. Local scan is complete. "
                f"Create a CRA-Shield workspace at {SIGNUP_URL}"
            ),
            "signup_url": SIGNUP_URL,
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
        return {"ok": False, "message": f"CRA-Shield ingest failed: {exc}"}
