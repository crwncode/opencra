from datetime import datetime, timezone

from opencra_shared.models import FailOn, SbomDocument, ScanResult, VulnMatch
from opencra_shared.sbom import normalize_purl, parse_cyclonedx

SAMPLE = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.6",
    "serialNumber": "urn:uuid:11111111-1111-1111-1111-111111111111",
    "version": 1,
    "metadata": {
        "timestamp": "2026-09-08T21:00:00Z",
        "component": {"name": "acme-app", "version": "1.4.2", "type": "application"},
        "tools": {"components": [{"name": "syft", "version": "1.18.0"}]},
    },
    "components": [
        {
            "type": "library",
            "name": "requests",
            "version": "2.31.0",
            "purl": "pkg:pypi/requests@2.31.0",
            "licenses": [{"license": {"id": "Apache-2.0"}}],
        },
        {
            "type": "library",
            "name": "broken",
            "version": "1.0.0",
            "purl": "not a purl at all!!!",
        },
        {
            "type": "library",
            "name": "weird",
            "version": "1.0.0",
            "purl": "pkg:pypi/weird@1.0.0?bad=%%%",
        },
    ],
}


def test_normalize_valid_purl() -> None:
    assert normalize_purl("pkg:pypi/requests@2.31.0") == "pkg:pypi/requests@2.31.0"


def test_normalize_drops_invalid_purl() -> None:
    assert normalize_purl("not a purl") is None
    assert normalize_purl("") is None


def test_normalize_strips_broken_qualifiers() -> None:
    repaired = normalize_purl("pkg:pypi/weird@1.0.0?bad=%%%")
    assert repaired == "pkg:pypi/weird@1.0.0"


def test_parse_cyclonedx_skips_invalid_does_not_abort() -> None:
    doc = parse_cyclonedx(SAMPLE)
    assert doc.metadata.name == "acme-app"
    by_name = {c.name: c for c in doc.components}
    assert by_name["requests"].purl == "pkg:pypi/requests@2.31.0"
    assert by_name["broken"].purl is None
    assert by_name["broken"].skipped_reason is not None
    assert by_name["weird"].purl == "pkg:pypi/weird@1.0.0"


def test_fail_on_kev_and_severity() -> None:
    result = ScanResult(
        target=".",
        scanned_at=datetime.now(timezone.utc),
        sbom=SbomDocument(),
        matches=[
            VulnMatch(purl="pkg:pypi/x@1", severity="HIGH", in_kev=False),
            VulnMatch(purl="pkg:pypi/y@1", severity="LOW", in_kev=True, cve_id="CVE-2024-0001"),
        ],
    )
    assert result.fails(FailOn.KEV)
    assert result.fails(FailOn.HIGH)
    assert not result.fails(FailOn.CRITICAL)
    assert not result.fails(FailOn.NONE)
