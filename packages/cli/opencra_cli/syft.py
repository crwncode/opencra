"""Safe Syft subprocess wrapper. Never uses shell=True."""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
from pathlib import Path
from typing import Any

from opencra_shared.sbom import parse_cyclonedx

logger = logging.getLogger("opencra.syft")

MIN_SYFT_VERSION = (1, 0, 0)
INSTALL_HINT = (
    "Syft is required. Install it, then re-run:\n"
    "  macOS:  brew install syft\n"
    "  Linux:  curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh "
    "| sh -s -- -b ~/.local/bin"
)


class SyftError(Exception):
    def __init__(self, message: str, *, exit_code: int = 2) -> None:
        super().__init__(message)
        self.exit_code = exit_code


def resolve_syft(syft_bin: str | None = None) -> str:
    if syft_bin:
        path = Path(syft_bin).expanduser()
        if path.is_file():
            return str(path)
        which = shutil.which(syft_bin)
        if which:
            return which
        raise SyftError(f"Syft binary not found at {syft_bin}.\n{INSTALL_HINT}")
    found = shutil.which("syft")
    if not found:
        raise SyftError(f"Syft is not on PATH.\n{INSTALL_HINT}")
    return found


def parse_syft_version(text: str) -> tuple[int, int, int] | None:
    # Typical: "syft 1.18.1"
    for token in text.replace(",", " ").split():
        parts = token.strip().split(".")
        if len(parts) >= 2 and parts[0].isdigit() and parts[1].isdigit():
            patch = int(parts[2]) if len(parts) > 2 and parts[2].isdigit() else 0
            return int(parts[0]), int(parts[1]), patch
    return None


def syft_version(syft_bin: str | None = None) -> tuple[str, tuple[int, int, int] | None]:
    binary = resolve_syft(syft_bin)
    result = subprocess.run(
        [binary, "version"],
        capture_output=True,
        text=True,
        check=False,
    )
    output = (result.stdout or "") + (result.stderr or "")
    if result.returncode != 0:
        # Older syft prints version via --version
        result = subprocess.run(
            [binary, "--version"],
            capture_output=True,
            text=True,
            check=False,
        )
        output = (result.stdout or "") + (result.stderr or "")
    parsed = parse_syft_version(output)
    return output.strip().splitlines()[0] if output.strip() else binary, parsed


def version_ok(version: tuple[int, int, int] | None) -> bool:
    if version is None:
        return True
    return version >= MIN_SYFT_VERSION


def scan_target(target: str, *, syft_bin: str | None = None) -> dict[str, Any]:
    binary = resolve_syft(syft_bin)
    cmd = [binary, "scan", target, "-o", "cyclonedx-json"]
    logger.debug("Running %s", cmd)
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=True,
        )
    except subprocess.CalledProcessError as exc:
        stderr = (exc.stderr or exc.stdout or "").strip()
        raise SyftError(f"Syft failed on {target}: {stderr or exc}") from exc
    except FileNotFoundError as exc:
        raise SyftError(f"Syft is not on PATH.\n{INSTALL_HINT}") from exc

    stdout = result.stdout.strip()
    if not stdout:
        raise SyftError("Syft produced empty CycloneDX output.")
    try:
        payload = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise SyftError(f"Syft output is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise SyftError("Syft output is not a CycloneDX object.")
    return payload


def scan_to_document(target: str, *, syft_bin: str | None = None):
    return parse_cyclonedx(scan_target(target, syft_bin=syft_bin))
