"""OpenCRA state directory. Default ``~/.opencra``; override with ``OPENCRA_HOME``."""

from __future__ import annotations

import os
from pathlib import Path


def opencra_home() -> Path:
    """Return the OpenCRA state directory (cache, managed binaries)."""
    override = os.environ.get("OPENCRA_HOME")
    if override:
        return Path(override).expanduser()
    return Path.home() / ".opencra"
