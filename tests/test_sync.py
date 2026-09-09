from datetime import datetime, timezone

import httpx
from opencra_cli.sync import ingest
from opencra_shared.models import SbomDocument, SbomMetadata, ScanResult


def _result() -> ScanResult:
    return ScanResult(
        target=".",
        scanned_at=datetime.now(timezone.utc),
        sbom=SbomDocument(metadata=SbomMetadata(name="acme-app")),
    )


def test_ingest_skips_without_url_or_key(monkeypatch) -> None:
    monkeypatch.delenv("OPENCRA_API_URL", raising=False)
    monkeypatch.delenv("OPENCRA_API_KEY", raising=False)
    out = ingest(_result())
    assert out["ok"] is False
    assert out["skipped"] is True
    assert "OPENCRA_API_URL" in out["message"]
    assert "OPENCRA_API_KEY" in out["message"]
    assert "cra-shield" not in out["message"].lower()
    assert "crashield" not in out["message"].lower()
    assert "signup_url" not in out


def test_ingest_skips_without_url_even_with_key(monkeypatch) -> None:
    monkeypatch.delenv("OPENCRA_API_URL", raising=False)
    monkeypatch.setenv("OPENCRA_API_KEY", "secret")
    out = ingest(_result())
    assert out["skipped"] is True
    assert "OPENCRA_API_URL" in out["message"]


def test_ingest_skips_without_key_even_with_url(monkeypatch) -> None:
    monkeypatch.setenv("OPENCRA_API_URL", "http://127.0.0.1:8000")
    monkeypatch.delenv("OPENCRA_API_KEY", raising=False)
    out = ingest(_result())
    assert out["skipped"] is True
    assert "OPENCRA_API_KEY" in out["message"]


def test_ingest_posts_only_when_both_set(monkeypatch) -> None:
    monkeypatch.setenv("OPENCRA_API_URL", "http://127.0.0.1:8000")
    monkeypatch.setenv("OPENCRA_API_KEY", "secret")

    class _Response:
        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict:
            return {"accepted": True}

    class _Client:
        def __enter__(self) -> "_Client":
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def post(self, url: str, json: dict, headers: dict) -> _Response:
            assert url == "http://127.0.0.1:8000/v1/ingest"
            assert headers["Authorization"] == "Bearer secret"
            assert json["target"] == "."
            return _Response()

    monkeypatch.setattr("opencra_cli.sync.client", lambda: _Client())
    out = ingest(_result())
    assert out == {"ok": True, "response": {"accepted": True}}


def test_ingest_reports_http_error_without_brand(monkeypatch) -> None:
    monkeypatch.setenv("OPENCRA_API_URL", "http://127.0.0.1:8000")
    monkeypatch.setenv("OPENCRA_API_KEY", "secret")

    class _Client:
        def __enter__(self) -> "_Client":
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def post(self, url: str, json: dict, headers: dict) -> None:
            raise httpx.ConnectError("refused")

    monkeypatch.setattr("opencra_cli.sync.client", lambda: _Client())
    out = ingest(_result())
    assert out["ok"] is False
    assert "Cloud ingest failed" in out["message"]
    assert "CRA-Shield" not in out["message"]
