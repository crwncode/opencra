"""Optional Slack / Teams deadline webhooks (Pro+)."""

from __future__ import annotations

import logging

import httpx

from opencra_api.config import settings

logger = logging.getLogger("crashield.notify")


def notify_deadline(text: str) -> None:
    urls = [u for u in (settings.slack_webhook_url, settings.teams_webhook_url) if u]
    if not urls:
        return
    for url in urls:
        try:
            with httpx.Client(timeout=10.0) as client:
                if "office.com" in url or "webhook.office" in url:
                    client.post(url, json={"text": text})
                else:
                    client.post(url, json={"text": text})
        except httpx.HTTPError as exc:
            logger.warning("Webhook failed: %s", exc)
