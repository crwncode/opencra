from __future__ import annotations

from pathlib import Path

import httpx
from opencra_cli.db import Cache
from opencra_cli.osv import hydrate_vulns, query_batch

LOG4J_PURL = "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"
LOG4SHELL = "GHSA-jfh8-c2jp-5v3q"


def _mock_client(monkeypatch, handler) -> None:
    transport = httpx.MockTransport(handler)

    def factory(**kwargs: object) -> httpx.Client:
        return httpx.Client(transport=transport, timeout=10.0, **kwargs)

    monkeypatch.setattr("opencra_cli.osv.client", factory)


def test_hydrate_offline_does_not_hit_network(tmp_path: Path, monkeypatch) -> None:
    def boom(**kwargs: object) -> httpx.Client:
        raise AssertionError("offline hydrate must not open HTTP")

    monkeypatch.setattr("opencra_cli.osv.client", boom)
    stubs = [{"id": LOG4SHELL, "modified": "2025-01-01T00:00:00Z"}]
    with Cache(tmp_path / "cache.db") as cache:
        out = hydrate_vulns(stubs, cache, offline=True)
    assert out == stubs


def test_querybatch_stubs_are_hydrated_for_kev(tmp_path: Path, monkeypatch) -> None:
    urls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        urls.append(str(request.url))
        if request.url.path.endswith("/querybatch"):
            return httpx.Response(
                200,
                json={
                    "results": [
                        {
                            "vulns": [
                                {"id": LOG4SHELL, "modified": "2025-10-22T19:37:02Z"},
                            ]
                        }
                    ]
                },
            )
        if request.url.path.endswith(f"/vulns/{LOG4SHELL}"):
            return httpx.Response(
                200,
                json={
                    "id": LOG4SHELL,
                    "aliases": ["CVE-2021-44228"],
                    "summary": "Log4Shell",
                    "database_specific": {"severity": "CRITICAL"},
                },
            )
        return httpx.Response(404, text="unexpected")

    _mock_client(monkeypatch, handler)
    with Cache(tmp_path / "cache.db") as cache:
        results = query_batch([LOG4J_PURL], cache)
        vulns = results[LOG4J_PURL]
        assert vulns[0]["aliases"] == ["CVE-2021-44228"]
        assert cache.get_osv(LOG4J_PURL)[0]["aliases"] == ["CVE-2021-44228"]

        urls.clear()
        again = query_batch([LOG4J_PURL], cache)
        assert again[LOG4J_PURL][0]["aliases"] == ["CVE-2021-44228"]
        assert urls == []


def test_hydrate_repairs_cached_querybatch_stubs(tmp_path: Path, monkeypatch) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith(f"/vulns/{LOG4SHELL}"):
            return httpx.Response(
                200,
                json={"id": LOG4SHELL, "aliases": ["CVE-2021-44228"]},
            )
        return httpx.Response(500, text="querybatch should not run")

    _mock_client(monkeypatch, handler)
    with Cache(tmp_path / "cache.db") as cache:
        cache.save_osv(LOG4J_PURL, [{"id": LOG4SHELL, "modified": "2025-01-01T00:00:00Z"}])
        results = query_batch([LOG4J_PURL], cache)
    assert results[LOG4J_PURL][0]["aliases"] == ["CVE-2021-44228"]
