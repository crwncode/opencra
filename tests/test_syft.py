from __future__ import annotations

import hashlib
import io
import json
import tarfile
from pathlib import Path

import httpx
import pytest
from opencra_cli.app import app
from opencra_cli.db import default_db_path
from opencra_cli.httputil import DOWNLOAD_TIMEOUT, USER_AGENT, client
from opencra_cli.paths import opencra_home
from opencra_cli.syft import (
    INSTALL_HINT,
    SyftError,
    ensure_syft,
    find_syft,
    format_syft_label,
    install_managed_syft,
    load_cyclonedx_file,
    managed_syft_path,
    parse_checksums,
    parse_syft_version,
    resolve_syft,
    scan_to_document,
    syft_archive_name,
    syft_platform,
    version_ok,
)
from typer.testing import CliRunner

SAMPLE_CDX = Path(__file__).resolve().parents[1] / "examples" / "sample.cdx.json"

SYFT_VERSION_BLOCK = """
Application:   syft
Version:       1.51.1
BuildDate:     2026-08-27T16:55:02Z
GitDescription: v1.51.1
SchemaVersion: 16.1.10
""".strip()

FAKE_SYFT_SCRIPT = """#!/bin/sh
if [ "$1" = "version" ] || [ "$1" = "--version" ]; then
  echo "syft 1.18.1"
  exit 0
fi
cat <<'EOF'
{"bomFormat":"CycloneDX","specVersion":"1.6","metadata":{"component":{"name":"demo","type":"application"}},"components":[]}
EOF
"""


def _touch_executable(path: Path, body: str = "#!/bin/sh\nexit 0\n") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")
    path.chmod(0o755)
    return path


def _isolate_syft(monkeypatch: pytest.MonkeyPatch, home: Path) -> None:
    monkeypatch.setenv("OPENCRA_HOME", str(home))
    monkeypatch.setattr("opencra_cli.syft.which_syft", lambda: None)
    monkeypatch.setattr("opencra_cli.app.which_syft", lambda: None)


def _make_syft_archive(payload: bytes = b"#!/bin/sh\necho syft\n") -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        info = tarfile.TarInfo(name="syft")
        info.size = len(payload)
        info.mode = 0o755
        tf.addfile(info, io.BytesIO(payload))
    return buf.getvalue()


def _mock_syft_download(
    monkeypatch: pytest.MonkeyPatch,
    *,
    archive: bytes | None = None,
    checksum: str | None = None,
    tag: str = "v1.18.1",
) -> list[str]:
    blob = archive if archive is not None else _make_syft_archive()
    os_name, arch = syft_platform()
    archive_name = syft_archive_name(tag, os_name, arch)
    checksum_name = f"syft_{tag.lstrip('vV')}_checksums.txt"
    digest = checksum if checksum is not None else hashlib.sha256(blob).hexdigest()
    checksums = f"{digest}  {archive_name}\n"
    urls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        urls.append(str(request.url))
        assert request.headers.get("user-agent") == USER_AGENT
        url = str(request.url)
        if url.rstrip("/").endswith("/releases/latest"):
            return httpx.Response(
                200,
                json={
                    "tag_name": tag,
                    "assets": [
                        {
                            "name": archive_name,
                            "browser_download_url": f"https://github.com/anchore/syft/releases/download/{tag}/{archive_name}",
                        },
                        {
                            "name": checksum_name,
                            "browser_download_url": f"https://github.com/anchore/syft/releases/download/{tag}/{checksum_name}",
                        },
                    ],
                },
            )
        if url.endswith(checksum_name):
            return httpx.Response(200, text=checksums)
        if url.endswith(archive_name):
            return httpx.Response(200, content=blob)
        return httpx.Response(404, text="unexpected url")

    transport = httpx.MockTransport(handler)

    def factory(**kwargs: object) -> httpx.Client:
        return client(transport=transport, **kwargs)

    monkeypatch.setattr("opencra_cli.syft.client", factory)
    return urls


def test_parse_syft_version() -> None:
    assert parse_syft_version("syft 1.18.1") == (1, 18, 1)
    assert parse_syft_version("1.0.0") == (1, 0, 0)
    assert parse_syft_version(SYFT_VERSION_BLOCK) == (1, 51, 1)
    assert parse_syft_version("Version: v1.18.1") == (1, 18, 1)


def test_format_syft_label_uses_parsed_version_not_application_line() -> None:
    parsed = parse_syft_version(SYFT_VERSION_BLOCK)
    assert format_syft_label(SYFT_VERSION_BLOCK, parsed) == "syft 1.51.1"
    assert format_syft_label(SYFT_VERSION_BLOCK, None) == "syft 1.51.1"
    assert format_syft_label("", None, fallback="/usr/bin/syft") == "/usr/bin/syft"


def test_min_version() -> None:
    assert version_ok((1, 0, 0))
    assert not version_ok((0, 9, 0))


def test_load_cyclonedx_file_reads_sample() -> None:
    payload = load_cyclonedx_file(SAMPLE_CDX)
    assert payload is not None
    assert payload["bomFormat"] == "CycloneDX"
    assert payload["metadata"]["component"]["name"] == "acme-app"


def test_load_cyclonedx_file_rejects_non_cdx(tmp_path: Path) -> None:
    other = tmp_path / "notes.json"
    other.write_text('{"hello": "world"}', encoding="utf-8")
    assert load_cyclonedx_file(other) is None
    assert load_cyclonedx_file(tmp_path / "missing.json") is None


def test_opencra_home_and_managed_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPENCRA_HOME", str(tmp_path / "state"))
    monkeypatch.delenv("OPENCRA_CACHE", raising=False)
    assert opencra_home() == tmp_path / "state"
    assert default_db_path() == tmp_path / "state" / "cache.db"
    assert managed_syft_path() == tmp_path / "state" / "bin" / "syft"
    monkeypatch.setenv("OPENCRA_CACHE", str(tmp_path / "custom.db"))
    assert default_db_path() == tmp_path / "custom.db"


def test_syft_platform_linux_amd64() -> None:
    assert syft_platform("linux", "x86_64") == ("linux", "amd64")
    assert syft_platform("darwin", "arm64") == ("darwin", "arm64")
    assert syft_platform("win32", "AMD64") == ("windows", "amd64")
    assert syft_archive_name("v1.18.1", "linux", "amd64") == "syft_1.18.1_linux_amd64.tar.gz"
    assert syft_archive_name("1.18.1", "windows", "amd64") == "syft_1.18.1_windows_amd64.zip"


def test_syft_platform_rejects_unknown() -> None:
    with pytest.raises(SyftError, match="architecture"):
        syft_platform("linux", "mips")
    with pytest.raises(SyftError, match="OS"):
        syft_platform("plan9", "amd64")


def test_parse_checksums() -> None:
    text = "abc123  syft_1.18.1_linux_amd64.tar.gz\ndef456 *syft_1.18.1_darwin_arm64.tar.gz\n"
    assert parse_checksums(text, "syft_1.18.1_linux_amd64.tar.gz") == "abc123"
    assert parse_checksums(text, "syft_1.18.1_darwin_arm64.tar.gz") == "def456"
    assert parse_checksums(text, "missing.tar.gz") is None


def test_resolve_order_explicit_wins(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _isolate_syft(monkeypatch, tmp_path / "home")
    explicit = _touch_executable(tmp_path / "custom" / "syft")
    path_bin = _touch_executable(tmp_path / "path" / "syft")
    managed = _touch_executable(managed_syft_path())
    monkeypatch.setattr("opencra_cli.syft.which_syft", lambda: str(path_bin))
    found, source = find_syft(str(explicit))
    assert found == str(explicit)
    assert source == "explicit"
    assert resolve_syft(str(explicit)) == str(explicit)
    assert managed.is_file()


def test_resolve_order_path_before_managed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _isolate_syft(monkeypatch, tmp_path / "home")
    path_bin = _touch_executable(tmp_path / "path" / "syft")
    _touch_executable(managed_syft_path())
    monkeypatch.setattr("opencra_cli.syft.which_syft", lambda: str(path_bin))
    found, source = find_syft()
    assert found == str(path_bin)
    assert source == "path"


def test_resolve_order_managed_fallback(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _isolate_syft(monkeypatch, tmp_path / "home")
    managed = _touch_executable(managed_syft_path())
    found, source = find_syft()
    assert found == str(managed)
    assert source == "managed"
    assert resolve_syft() == str(managed)


def test_resolve_missing_raises(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _isolate_syft(monkeypatch, tmp_path / "home")
    with pytest.raises(SyftError, match="not on PATH"):
        resolve_syft()


def test_explicit_missing_does_not_fallback(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _isolate_syft(monkeypatch, tmp_path / "home")
    _touch_executable(managed_syft_path())
    with pytest.raises(SyftError, match="not found at"):
        find_syft(str(tmp_path / "no-such-syft"))


def test_offline_ensure_refuses_download(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _isolate_syft(monkeypatch, tmp_path / "home")

    def boom_client(**kwargs: object) -> httpx.Client:
        raise AssertionError("offline must not open an HTTP client")

    def boom_install(*, force: bool = False) -> str:
        raise AssertionError("offline must not download")

    monkeypatch.setattr("opencra_cli.syft.client", boom_client)
    monkeypatch.setattr("opencra_cli.syft.install_managed_syft", boom_install)
    with pytest.raises(SyftError, match="--offline does not download"):
        ensure_syft(offline=True)


def test_offline_ensure_includes_brew_hint(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _isolate_syft(monkeypatch, tmp_path / "home")
    with pytest.raises(SyftError, match="brew install syft") as exc:
        ensure_syft(offline=True)
    assert "--offline" in str(exc.value)
    assert "install.sh" in str(exc.value)


def test_install_managed_syft_mocked(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _isolate_syft(monkeypatch, tmp_path / "home")
    payload = b"#!/bin/sh\necho installed\n"
    archive = _make_syft_archive(payload)
    urls = _mock_syft_download(monkeypatch, archive=archive)
    path = install_managed_syft()
    dest = managed_syft_path()
    assert path == str(dest)
    assert dest.is_file()
    assert dest.read_bytes() == payload
    assert dest.stat().st_mode & 0o111
    assert any("releases/latest" in url for url in urls)
    assert any("checksums.txt" in url for url in urls)


def test_install_managed_syft_rejects_bad_checksum(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _isolate_syft(monkeypatch, tmp_path / "home")
    _mock_syft_download(monkeypatch, checksum="0" * 64)
    with pytest.raises(SyftError, match="checksum mismatch"):
        install_managed_syft()
    assert not managed_syft_path().exists()


def test_ensure_syft_auto_installs_when_online(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _isolate_syft(monkeypatch, tmp_path / "home")
    announced: list[Path] = []
    _mock_syft_download(monkeypatch)
    path = ensure_syft(offline=False, on_install=announced.append)
    assert path == str(managed_syft_path())
    assert announced == [managed_syft_path().parent]


def test_scan_to_document_cdx_skips_syft(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _isolate_syft(monkeypatch, tmp_path / "home")

    def boom(*args: object, **kwargs: object) -> str:
        raise AssertionError("CycloneDX file scan must not require Syft")

    monkeypatch.setattr("opencra_cli.syft.ensure_syft", boom)
    monkeypatch.setattr("opencra_cli.syft.install_managed_syft", boom)
    document = scan_to_document(str(SAMPLE_CDX), offline=False)
    assert document.metadata.name == "acme-app"


def test_scan_dir_offline_without_syft_exits_2(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _isolate_syft(monkeypatch, tmp_path / "home")
    monkeypatch.setenv("OPENCRA_CACHE", str(tmp_path / "cache.db"))
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "README.md").write_text("demo\n", encoding="utf-8")

    def boom(**kwargs: object) -> httpx.Client:
        raise AssertionError("--offline must not hit the network")

    monkeypatch.setattr("opencra_cli.syft.client", boom)
    monkeypatch.setattr("opencra_cli.kev.client", boom)
    monkeypatch.setattr("opencra_cli.osv.client", boom)
    monkeypatch.setattr(
        "opencra_cli.syft.install_managed_syft",
        lambda **kwargs: (_ for _ in ()).throw(AssertionError("offline must not download")),
    )

    result = CliRunner().invoke(app, ["scan", str(proj), "--offline", "--quiet"])
    assert result.exit_code == 2, result.stdout + result.stderr
    combined = (result.stdout + result.stderr).lower()
    assert "syft" in combined
    assert "brew" in combined
    assert "offline" in combined


def test_scan_dir_bootstraps_syft_when_online(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _isolate_syft(monkeypatch, tmp_path / "home")
    monkeypatch.setenv("OPENCRA_CACHE", str(tmp_path / "cache.db"))
    proj = tmp_path / "proj"
    proj.mkdir()

    def fake_install(*, force: bool = False) -> str:
        return str(_touch_executable(managed_syft_path(), FAKE_SYFT_SCRIPT))

    monkeypatch.setattr("opencra_cli.syft.install_managed_syft", fake_install)

    def kev_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"vulnerabilities": []})

    transport = httpx.MockTransport(kev_handler)

    def factory(**kwargs: object) -> httpx.Client:
        return client(transport=transport, **kwargs)

    monkeypatch.setattr("opencra_cli.kev.client", factory)
    monkeypatch.setattr("opencra_cli.osv.client", factory)
    monkeypatch.setattr("opencra_cli.osv.hydrate_vulns", lambda vulns, cache, offline=False: vulns)

    result = CliRunner().invoke(
        app, ["scan", str(proj), "--fail-on", "none", "--format", "json", "--quiet"]
    )
    assert result.exit_code == 0, result.stdout + result.stderr
    payload = json.loads(result.stdout)
    assert payload["sbom"]["metadata"]["name"] == "demo"
    assert managed_syft_path().is_file()


def test_scan_dir_announces_bootstrap(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _isolate_syft(monkeypatch, tmp_path / "home")
    monkeypatch.setenv("OPENCRA_CACHE", str(tmp_path / "cache.db"))
    proj = tmp_path / "proj"
    proj.mkdir()

    def fake_install(*, force: bool = False) -> str:
        return str(_touch_executable(managed_syft_path(), FAKE_SYFT_SCRIPT))

    monkeypatch.setattr("opencra_cli.syft.install_managed_syft", fake_install)
    transport = httpx.MockTransport(lambda request: httpx.Response(200, json={"vulnerabilities": []}))

    def factory(**kwargs: object) -> httpx.Client:
        return client(transport=transport, **kwargs)

    monkeypatch.setattr("opencra_cli.kev.client", factory)
    monkeypatch.setattr("opencra_cli.osv.client", factory)
    monkeypatch.setattr("opencra_cli.osv.hydrate_vulns", lambda vulns, cache, offline=False: vulns)

    result = CliRunner().invoke(app, ["scan", str(proj), "--fail-on", "none"])
    assert result.exit_code == 0, result.stdout + result.stderr
    combined = " ".join((result.stdout + result.stderr).split())
    assert "Syft is required" in combined
    assert "Downloading the official Anchore release" in combined
    assert str(managed_syft_path().parent) in combined


def test_doctor_reports_path_vs_managed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _isolate_syft(monkeypatch, tmp_path / "home")
    path_bin = _touch_executable(tmp_path / "path" / "syft", FAKE_SYFT_SCRIPT)
    managed = _touch_executable(managed_syft_path(), FAKE_SYFT_SCRIPT)
    monkeypatch.setattr("opencra_cli.syft.which_syft", lambda: str(path_bin))
    monkeypatch.setattr("opencra_cli.app.which_syft", lambda: str(path_bin))
    monkeypatch.setattr("opencra_cli.app.osv_ping", lambda: False)
    result = CliRunner().invoke(app, ["doctor"])
    assert result.exit_code == 0, result.stdout + result.stderr
    assert str(path_bin) in result.stdout
    assert str(managed) in result.stdout
    assert "PATH:" in result.stdout
    assert "managed:" in result.stdout


def test_doctor_missing_mentions_install_flag(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _isolate_syft(monkeypatch, tmp_path / "home")
    monkeypatch.setattr("opencra_cli.app.osv_ping", lambda: False)
    result = CliRunner().invoke(app, ["doctor"])
    assert result.exit_code == 0, result.stdout + result.stderr
    combined = result.stdout + result.stderr
    assert "missing" in combined.lower()
    assert "opencra doctor --install-syft" in combined
    assert "opencra scan ." in combined
    assert "brew install syft" in combined
    assert "PATH: not found" in combined
    assert "managed: not found" in combined
    assert "INSTALL_HINT" not in combined
    assert any(line for line in INSTALL_HINT.splitlines() if line and line in combined)


def test_doctor_install_syft_uses_mocked_download(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _isolate_syft(monkeypatch, tmp_path / "home")
    monkeypatch.setattr("opencra_cli.app.osv_ping", lambda: False)
    _mock_syft_download(monkeypatch, archive=_make_syft_archive(FAKE_SYFT_SCRIPT.encode()))
    result = CliRunner().invoke(app, ["doctor", "--install-syft"])
    assert result.exit_code == 0, result.stdout + result.stderr
    combined = " ".join((result.stdout + result.stderr).split())
    assert "Syft install: ok" in combined or "Syft install:" in combined
    assert managed_syft_path().is_file()
    assert "Downloading the official Anchore release" in combined


def test_download_timeout_is_sixty_seconds() -> None:
    assert DOWNLOAD_TIMEOUT == 60.0
    with client(timeout=DOWNLOAD_TIMEOUT) as http:
        assert http.timeout.read == 60.0
        assert http.headers["User-Agent"] == USER_AGENT
