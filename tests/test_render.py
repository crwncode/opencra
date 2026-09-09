from datetime import datetime, timezone
from io import StringIO

from opencra_cli.render import print_completion_banner
from opencra_shared.models import SbomDocument, SbomMetadata, ScanResult, VulnMatch
from rich.console import Console


def _result(matches: list[VulnMatch] | None = None) -> ScanResult:
    return ScanResult(
        target=".",
        scanned_at=datetime.now(timezone.utc),
        sbom=SbomDocument(metadata=SbomMetadata(name="acme-app")),
        matches=matches or [],
    )


def _text(result: ScanResult, *, synced: bool = False) -> str:
    buf = StringIO()
    console = Console(file=buf, force_terminal=True, color_system=None, width=100)
    print_completion_banner(result, console, synced=synced)
    return buf.getvalue()


def test_banner_zero_critical_mentions_sync_cloud() -> None:
    text = _text(_result())
    assert "Scan complete: 0 critical vulnerabilities found." in text
    assert "--sync-cloud" in text
    assert "https://cra-shield.com" in text
    assert "24h/72h" in text


def test_banner_kev_hit_leads_with_kev_count() -> None:
    text = _text(
        _result(
            [
                VulnMatch(
                    purl="pkg:pypi/demo@1.0.0",
                    cve_id="CVE-2021-44228",
                    severity="CRITICAL",
                    in_kev=True,
                )
            ]
        )
    )
    assert "1 CISA KEV candidate found." in text
    assert "--sync-cloud" in text


def test_banner_skips_upsell_after_sync() -> None:
    text = _text(_result(), synced=True)
    assert "Scan complete: 0 critical vulnerabilities found." in text
    assert "--sync-cloud" not in text
    assert "cra-shield.com" not in text
