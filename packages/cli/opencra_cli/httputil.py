"""Shared HTTP defaults: User-Agent and a hard 10s timeout."""

from __future__ import annotations

import httpx

from opencra_cli import __version__

USER_AGENT = f"opencra/{__version__}"
HTTP_TIMEOUT = 10.0


def client(**kwargs: object) -> httpx.Client:
    headers = {"User-Agent": USER_AGENT}
    extra = kwargs.pop("headers", None)
    if isinstance(extra, dict):
        headers.update(extra)
    return httpx.Client(timeout=HTTP_TIMEOUT, headers=headers, follow_redirects=True, **kwargs)  # type: ignore[arg-type]
