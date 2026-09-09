"""Safe Syft subprocess wrapper. Never uses shell=True."""

from __future__ import annotations

import hashlib
import io
import json
import logging
import os
import platform
import shutil
import stat
import subprocess
import sys
import tarfile
import zipfile
from collections.abc import Callable
from pathlib import Path
from typing import Any, Literal

import httpx
from opencra_shared.sbom import parse_cyclonedx

from opencra_cli.httputil import DOWNLOAD_TIMEOUT, client
from opencra_cli.paths import opencra_home

logger = logging.getLogger("opencra.syft")

MIN_SYFT_VERSION = (1, 0, 0)
SYFT_RELEASES_LATEST = "https://api.github.com/repos/anchore/syft/releases/latest"
SYFT_GITHUB_DOWNLOAD = "https://github.com/anchore/syft/releases/download"
InstallHook = Callable[[Path], None]

INSTALL_HINT = (
    "Syft is required. Install it, then re-run:\n"
    "  macOS:  brew install syft\n"
    "  Linux:  curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh "
    "| sh -s -- -b ~/.local/bin\n"
    "  Or:     opencra doctor --install-syft\n"
    "First online `opencra scan .` also downloads Syft once to ~/.opencra/bin."
)

OFFLINE_HINT = (
    "Syft is required for directory and image scans. --offline does not download it.\n"
    "  macOS:  brew install syft\n"
    "  Linux:  curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh "
    "| sh -s -- -b ~/.local/bin"
)

SyftSource = Literal["explicit", "path", "managed"]


class SyftError(Exception):
    def __init__(self, message: str, *, exit_code: int = 2) -> None:
        super().__init__(message)
        self.exit_code = exit_code


def managed_syft_path() -> Path:
    """``$OPENCRA_HOME/bin/syft`` (default ``~/.opencra/bin/syft``)."""
    name = "syft.exe" if sys.platform == "win32" else "syft"
    return opencra_home() / "bin" / name


def which_syft() -> str | None:
    return shutil.which("syft")


def _usable_binary(path: Path) -> bool:
    return path.is_file() and os.access(path, os.X_OK)


def syft_platform(system: str | None = None, machine: str | None = None) -> tuple[str, str]:
    """Map the current OS/arch to Anchore's GitHub release triplet (os, arch)."""
    sys_name = (system or sys.platform).lower()
    mach = (machine or platform.machine()).lower()
    if sys_name.startswith("linux"):
        os_name = "linux"
    elif sys_name in {"darwin", "macos", "osx"}:
        os_name = "darwin"
    elif sys_name.startswith("win"):
        os_name = "windows"
    else:
        raise SyftError(f"No official Syft build for this OS ({sys_name}).\n{INSTALL_HINT}")

    arch_map = {
        "x86_64": "amd64",
        "amd64": "amd64",
        "aarch64": "arm64",
        "arm64": "arm64",
        "ppc64le": "ppc64le",
        "s390x": "s390x",
        "riscv64": "riscv64",
    }
    arch = arch_map.get(mach)
    if arch is None:
        raise SyftError(f"No official Syft build for this architecture ({mach}).\n{INSTALL_HINT}")
    return os_name, arch


def syft_archive_name(version: str, os_name: str, arch: str) -> str:
    ver = version.lstrip("vV")
    suffix = ".zip" if os_name == "windows" else ".tar.gz"
    return f"syft_{ver}_{os_name}_{arch}{suffix}"


def parse_checksums(text: str, filename: str) -> str | None:
    """Return the SHA-256 hex digest for ``filename`` from an Anchore checksums.txt."""
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        listed = parts[-1].lstrip("*")
        if Path(listed).name == filename:
            return parts[0].lower()
    return None


def _extract_syft_bytes(archive: bytes, filename: str) -> bytes:
    """Extract only the Syft binary from a release archive. Never shell=True."""
    wanted = {"syft", "syft.exe"}
    if filename.endswith(".zip"):
        with zipfile.ZipFile(io.BytesIO(archive)) as zf:
            for info in zf.infolist():
                name = Path(info.filename).name
                if name in wanted and not info.is_dir():
                    if ".." in Path(info.filename).parts:
                        raise SyftError("Syft archive contained an unsafe path.")
                    return zf.read(info)
    else:
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as tf:
            for member in tf.getmembers():
                name = Path(member.name).name
                if name in wanted and member.isfile():
                    if ".." in Path(member.name).parts:
                        raise SyftError("Syft archive contained an unsafe path.")
                    extracted = tf.extractfile(member)
                    if extracted is None:
                        break
                    return extracted.read()
    raise SyftError("Syft archive did not contain a syft binary.")


def _write_managed_binary(data: bytes, dest: Path) -> str:
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_name(f".{dest.name}.tmp")
    tmp.write_bytes(data)
    tmp.chmod(tmp.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    tmp.replace(dest)
    return str(dest)


def _latest_release(http: httpx.Client) -> dict[str, Any]:
    response = http.get(
        SYFT_RELEASES_LATEST,
        headers={"Accept": "application/vnd.github+json"},
    )
    response.raise_for_status()
    payload = response.json()
    if not isinstance(payload, dict) or not payload.get("tag_name"):
        raise SyftError("GitHub latest Syft release JSON is missing tag_name.")
    return payload


def _asset_url(release: dict[str, Any], filename: str) -> str | None:
    for asset in release.get("assets") or []:
        if isinstance(asset, dict) and asset.get("name") == filename:
            url = asset.get("browser_download_url")
            if isinstance(url, str) and url.startswith("https://"):
                return url
    tag = str(release.get("tag_name") or "")
    if tag:
        return f"{SYFT_GITHUB_DOWNLOAD}/{tag}/{filename}"
    return None


def install_managed_syft(*, force: bool = False) -> str:
    """Download the official Anchore Syft release into ``~/.opencra/bin``.

    Uses HTTPS + User-Agent ``opencra/<ver>``. The GitHub release JSON call uses
    the shared 10s timeout; the binary archive uses ``DOWNLOAD_TIMEOUT`` (60s).
    Anchore checksums.txt is required and verified (SHA-256). Never ``shell=True``.
    """
    dest = managed_syft_path()
    if _usable_binary(dest) and not force:
        return str(dest)

    os_name, arch = syft_platform()
    try:
        with client() as http:
            release = _latest_release(http)
            version = str(release["tag_name"])
            archive_name = syft_archive_name(version, os_name, arch)
            checksum_name = f"syft_{version.lstrip('vV')}_checksums.txt"
            archive_url = _asset_url(release, archive_name)
            checksum_url = _asset_url(release, checksum_name)
            if not archive_url or not checksum_url:
                raise SyftError(
                    f"No official Syft asset {archive_name} on the latest release.\n{INSTALL_HINT}"
                )
            checksum_resp = http.get(checksum_url)
            checksum_resp.raise_for_status()
            expected = parse_checksums(checksum_resp.text, archive_name)
            if not expected:
                raise SyftError(f"Syft checksums.txt has no entry for {archive_name}.")

        with client(timeout=DOWNLOAD_TIMEOUT) as http:
            archive_resp = http.get(archive_url)
            archive_resp.raise_for_status()
            archive = archive_resp.content
    except httpx.HTTPError as exc:
        raise SyftError(f"Failed to download official Syft release: {exc}\n{INSTALL_HINT}") from exc

    digest = hashlib.sha256(archive).hexdigest()
    if digest != expected:
        raise SyftError(
            f"Syft checksum mismatch for {archive_name} "
            f"(expected {expected}, got {digest})."
        )

    binary = _extract_syft_bytes(archive, archive_name)
    path = _write_managed_binary(binary, dest)
    logger.info("Installed Syft %s to %s", version, path)
    return path


def find_syft(syft_bin: str | None = None) -> tuple[str, SyftSource] | None:
    """Locate Syft without downloading.

    Order: explicit ``--syft-bin`` → ``PATH`` (``shutil.which``) → managed
    ``~/.opencra/bin/syft``. An explicit path that does not exist raises.
    """
    if syft_bin:
        path = Path(syft_bin).expanduser()
        if path.is_file():
            return str(path), "explicit"
        which = shutil.which(syft_bin)
        if which:
            return which, "explicit"
        raise SyftError(f"Syft binary not found at {syft_bin}.\n{INSTALL_HINT}")
    found = which_syft()
    if found:
        return found, "path"
    managed = managed_syft_path()
    if _usable_binary(managed):
        return str(managed), "managed"
    return None


def resolve_syft(syft_bin: str | None = None) -> str:
    located = find_syft(syft_bin)
    if located:
        return located[0]
    raise SyftError(f"Syft is not on PATH or in {managed_syft_path()}.\n{INSTALL_HINT}")


def ensure_syft(
    syft_bin: str | None = None,
    *,
    offline: bool = False,
    auto_install: bool = True,
    on_install: InstallHook | None = None,
) -> str:
    """Resolve Syft, optionally downloading the official release when missing.

    ``--offline`` never downloads. Explicit ``--syft-bin`` is never replaced by
    a managed install.
    """
    located = find_syft(syft_bin)
    if located:
        return located[0]
    if offline:
        raise SyftError(OFFLINE_HINT)
    if not auto_install:
        raise SyftError(f"Syft is not on PATH or in {managed_syft_path()}.\n{INSTALL_HINT}")
    dest_dir = managed_syft_path().parent
    if on_install is not None:
        on_install(dest_dir)
    return install_managed_syft()


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


def scan_target(
    target: str,
    *,
    syft_bin: str | None = None,
    offline: bool = False,
    auto_install: bool = True,
    on_install: InstallHook | None = None,
) -> dict[str, Any]:
    binary = ensure_syft(
        syft_bin,
        offline=offline,
        auto_install=auto_install,
        on_install=on_install,
    )
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
        raise SyftError(f"Syft is not on PATH or in {managed_syft_path()}.\n{INSTALL_HINT}") from exc

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


def scan_to_document(
    target: str,
    *,
    syft_bin: str | None = None,
    offline: bool = False,
    auto_install: bool = True,
    on_install: InstallHook | None = None,
):
    payload = load_cyclonedx_file(Path(target).expanduser())
    if payload is not None:
        return parse_cyclonedx(payload)
    return parse_cyclonedx(
        scan_target(
            target,
            syft_bin=syft_bin,
            offline=offline,
            auto_install=auto_install,
            on_install=on_install,
        )
    )
