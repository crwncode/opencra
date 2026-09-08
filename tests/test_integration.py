"""Integration / regression tests for Phase 1 ship-blockers.

HTTP is mocked. Default pytest does not call live CISA.
A KEV match remains a candidate, never legal awareness.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path

import httpx
import pytest
from typer.testing import CliRunner

from opencra_cli import __version__
from opencra_cli.app import app
from opencra_cli.db import Cache
from opencra_cli.httputil import HTTP_TIMEOUT, USER_AGENT, client
from opencra_cli.kev import (
    KEV_FALLBACK_URL,
    KEV_URL,
    KevError,
    load_index,
    refresh,
)
from opencra_cli.pdf import export_report, weasyprint_status
from opencra_shared.models import SbomDocument, SbomMetadata, ScanResult

REPO_ROOT = Path(__file__).resolve().parents[1]
SAMPLE_CDX = REPO_ROOT / "examples" / "sample.cdx.json"

MINIMAL_KEV = {
    "vulnerabilities": [
        {
            "cveID": "CVE-2021-44228",
            "vendorProject": "Apache",
            "product": "Log4j",
            "vulnerabilityName": "Log4Shell",
            "dateAdded": "2021-12-10",
            "shortDescription": "test",
            "requiredAction": "Apply updates",
            "dueDate": "2021-12-24",
            "knownRansomwareCampaignUse": "Known",
        }
    ]
}


def _mock_client(monkeypatch: pytest.MonkeyPatch, handler) -> None:
    transport = httpx.MockTransport(handler)

    def factory(**kwargs: object) -> httpx.Client:
        return client(transport=transport, **kwargs)

    monkeypatch.setattr("opencra_cli.kev.client", factory)


def _assert_opencra_request(request: httpx.Request) -> None:
    assert request.headers.get("user-agent") == f"opencra/{__version__}"
    assert request.headers.get("user-agent") == USER_AGENT


def test_http_client_uses_versioned_ua_and_10s_timeout() -> None:
    assert USER_AGENT == f"opencra/{__version__}"
    assert HTTP_TIMEOUT == 10.0
    with client() as http:
        assert http.timeout.read == 10.0
        assert http.headers["User-Agent"] == USER_AGENT


def test_kev_primary_success_skips_fallback(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    urls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        _assert_opencra_request(request)
        urls.append(str(request.url))
        return httpx.Response(200, json=MINIMAL_KEV)

    _mock_client(monkeypatch, handler)
    with Cache(tmp_path / "cache.db") as cache:
        count, _fetched = refresh(cache)
        assert count == 1
        assert cache.get_kev_catalog() is not None
    assert urls == [KEV_URL]


def test_kev_fallback_when_primary_fails(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    urls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        _assert_opencra_request(request)
        urls.append(str(request.url))
        if str(request.url) == KEV_URL:
            return httpx.Response(404, text="not found")
        if str(request.url) == KEV_FALLBACK_URL:
            return httpx.Response(200, json=MINIMAL_KEV)
        return httpx.Response(500, text="unexpected url")

    _mock_client(monkeypatch, handler)
    with Cache(tmp_path / "cache.db") as cache:
        count, _fetched = refresh(cache)
        assert count == 1
        catalog = cache.get_kev_catalog()
        assert catalog is not None
        assert catalog["vulnerabilities"][0]["cveID"] == "CVE-2021-44228"
    assert urls == [KEV_URL, KEV_FALLBACK_URL]


def test_kev_both_sources_fail_clear_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        _assert_opencra_request(request)
        return httpx.Response(503, text="unavailable")

    _mock_client(monkeypatch, handler)
    with Cache(tmp_path / "cache.db") as cache:
        with pytest.raises(KevError, match="Failed to download CISA KEV catalog"):
            refresh(cache)
        assert cache.get_kev_catalog() is None


def test_offline_load_index_does_not_hit_network(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(**kwargs: object) -> httpx.Client:
        raise AssertionError("offline mode must not open an HTTP client")

    monkeypatch.setattr("opencra_cli.kev.client", boom)
    with Cache(tmp_path / "cache.db") as cache:
        cache.save_kev_catalog(MINIMAL_KEV)
        index = load_index(cache, offline=True)
    assert "CVE-2021-44228" in index


def test_offline_empty_cache_errors_without_network(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(**kwargs: object) -> httpx.Client:
        raise AssertionError("offline mode must not open an HTTP client")

    monkeypatch.setattr("opencra_cli.kev.client", boom)
    with Cache(tmp_path / "empty.db") as cache:
        with pytest.raises(KevError, match="No cached CISA KEV catalog"):
            load_index(cache, offline=True)


def test_pdf_fallback_when_weasyprint_unavailable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "opencra_cli.pdf.weasyprint_status",
        lambda: (False, "WeasyPrint native libraries missing: cairo/pango (test)"),
    )
    result = ScanResult(
        target=str(SAMPLE_CDX),
        scanned_at=datetime.now(timezone.utc),
        sbom=SbomDocument(metadata=SbomMetadata(name="acme-app")),
        matches=[],
    )
    dest = tmp_path / "cra-report.pdf"
    written = export_report(result, dest)
    assert written.suffix == ".html"
    assert written.exists()
    html = written.read_text(encoding="utf-8")
    assert "OpenCRA" in html
    assert "candidate" in html.lower() or "awareness" in html.lower()
    md_path = written.with_suffix(".md")
    assert md_path.exists()
    assert "OpenCRA" in md_path.read_text(encoding="utf-8")
    note = written.with_suffix(".pdf-fallback.txt").read_text(encoding="utf-8")
    assert "WeasyPrint" in note
    assert not dest.exists()


def test_weasyprint_status_documents_fallback_without_natives() -> None:
    """Do not require Cairo/Pango; just document the engine status."""
    ok, reason = weasyprint_status()
    if ok:
        assert "WeasyPrint" in reason
        return
    lowered = reason.lower()
    assert "weasyprint" in lowered or "cairo" in lowered or "pango" in lowered


def test_scan_fail_on_defaults_to_kev() -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["scan", "--help"])
    assert result.exit_code == 0
    help_text = result.stdout
    assert "--fail-on" in help_text
    assert "kev" in help_text


def test_scan_sample_cdx_offline_without_syft(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cache_path = tmp_path / "cache.db"
    monkeypatch.setenv("OPENCRA_CACHE", str(cache_path))

    def boom(**kwargs: object) -> httpx.Client:
        raise AssertionError("--offline must not hit the network")

    monkeypatch.setattr("opencra_cli.kev.client", boom)
    monkeypatch.setattr("opencra_cli.osv.client", boom)

    with Cache(cache_path) as cache:
        cache.save_kev_catalog(MINIMAL_KEV)

    out = tmp_path / "result.json"
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "scan",
            str(SAMPLE_CDX),
            "--offline",
            "--format",
            "json",
            "--output",
            str(out),
            "--quiet",
        ],
    )
    assert result.exit_code == 0, result.stdout + result.stderr
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["offline"] is True
    assert payload["sbom"]["metadata"]["name"] == "acme-app"
    names = [c["name"] for c in payload["sbom"]["components"]]
    assert "requests" in names
    # Offline + empty OSV cache => no matches; default --fail-on kev still exits 0.
    assert payload["matches"] == []


def test_scan_offline_without_kev_cache_exits_2(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("OPENCRA_CACHE", str(tmp_path / "empty.db"))

    def boom(**kwargs: object) -> httpx.Client:
        raise AssertionError("--offline must not hit the network")

    monkeypatch.setattr("opencra_cli.kev.client", boom)
    monkeypatch.setattr("opencra_cli.osv.client", boom)

    runner = CliRunner()
    result = runner.invoke(app, ["scan", str(SAMPLE_CDX), "--offline", "--quiet"])
    assert result.exit_code == 2
    combined = (result.stdout + result.stderr).lower()
    assert "cached" in combined or "offline" in combined


@pytest.mark.network
@pytest.mark.skipif(
    not os.environ.get("OPENCRA_NETWORK_TESTS"),
    reason="live CISA KEV download; set OPENCRA_NETWORK_TESTS=1 to enable",
)
def test_live_kev_refresh(tmp_path: Path) -> None:
    with Cache(tmp_path / "live.db") as cache:
        count, fetched = refresh(cache)
    assert count > 0
    assert fetched is not None
