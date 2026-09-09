"""OpenCRA state directory. Default ``~/.opencra``; override with ``OPENCRA_HOME``."""

from __future__ import annotations

import os
from pathlib import Path

FIRST_RUN_MARKER = ".first_run_done"


def opencra_home() -> Path:
    """Return the OpenCRA state directory (cache, managed binaries)."""
    override = os.environ.get("OPENCRA_HOME")
    if override:
        return Path(override).expanduser()
    return Path.home() / ".opencra"


def first_run_marker_path() -> Path:
    """``$OPENCRA_HOME/.first_run_done`` — set after the one-time usage tip."""
    return opencra_home() / FIRST_RUN_MARKER
