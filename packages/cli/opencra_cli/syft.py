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


def _parse_version_token(text: str) -> tuple[int, int, int] | None:
    for token in text.replace(",", " ").split():
        token = token.strip().lstrip("vV")
        parts = token.split(".")
        if len(parts) >= 2 and parts[0].isdigit() and parts[1].isdigit():
            patch = int(parts[2]) if len(parts) > 2 and parts[2].isdigit() else 0
            return int(parts[0]), int(parts[1]), patch
    return None


def parse_syft_version(text: str) -> tuple[int, int, int] | None:
    """Parse a Syft version from `syft version` or `syft --version` text.

    Prefer the ``Version:`` line so SchemaVersion (e.g. 16.1.10) is not used.
    """
    for line in text.splitlines():
        if line.strip().lower().startswith("version:"):
            parsed = _parse_version_token(line.split(":", 1)[1])
            if parsed:
                return parsed
    return _parse_version_token(text)


def format_syft_label(output: str, parsed: tuple[int, int, int] | None, fallback: str = "syft") -> str:
    """Human-readable Syft version for `opencra doctor` (not the first metadata line)."""
    if parsed:
        return f"syft {parsed[0]}.{parsed[1]}.{parsed[2]}"
    for line in output.splitlines():
        if line.strip().lower().startswith("version:"):
            value = line.split(":", 1)[1].strip()
            if value:
                return f"syft {value.lstrip('vV')}"
    stripped = output.strip()
    if stripped:
        return stripped.splitlines()[0]
    return fallback


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
    return format_syft_label(output, parsed, fallback=binary), parsed


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


def load_cyclonedx_file(path: Path) -> dict[str, Any] | None:
    """Return a CycloneDX object if path is an existing CDX JSON file."""
    if not path.is_file():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict):
        return None
    if str(payload.get("bomFormat") or "").lower() == "cyclonedx":
        return payload
    return None


def scan_to_document(target: str, *, syft_bin: str | None = None):
    payload = load_cyclonedx_file(Path(target).expanduser())
    if payload is not None:
        return parse_cyclonedx(payload)
    return parse_cyclonedx(scan_target(target, syft_bin=syft_bin))
