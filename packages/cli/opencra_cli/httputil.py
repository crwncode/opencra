"""Shared HTTP defaults: User-Agent and a hard 10s timeout."""

from __future__ import annotations

import httpx

from opencra_cli import __version__

USER_AGENT = f"opencra/{__version__}"
HTTP_TIMEOUT = 10.0
# Official Syft archives are ~25–30 MB; allow a longer read timeout for the binary only.
DOWNLOAD_TIMEOUT = 60.0


def client(**kwargs: object) -> httpx.Client:
    headers = {"User-Agent": USER_AGENT}
    extra = kwargs.pop("headers", None)
    if isinstance(extra, dict):
        headers.update(extra)
    timeout = kwargs.pop("timeout", HTTP_TIMEOUT)
    return httpx.Client(timeout=timeout, headers=headers, follow_redirects=True, **kwargs)  # type: ignore[arg-type]
