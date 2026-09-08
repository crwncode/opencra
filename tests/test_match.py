from opencra_cli.match import merge_matches
from opencra_shared.kev import KevEntry
from opencra_shared.models import Component


def test_merge_flags_kev() -> None:
    components = [Component(name="log4j", version="2.14.1", purl="pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1")]
    osv = {
        "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1": [
            {
                "id": "GHSA-xxxx",
                "aliases": ["CVE-2021-44228"],
                "summary": "Log4Shell",
                "database_specific": {"severity": "CRITICAL"},
            }
        ]
    }
    kev = {
        "CVE-2021-44228": KevEntry(
            cve_id="CVE-2021-44228",
            known_ransomware="Known",
        )
    }
    matches = merge_matches(components, osv, kev)
    assert len(matches) == 1
    assert matches[0].in_kev is True
    assert matches[0].cve_id == "CVE-2021-44228"
    assert matches[0].severity == "CRITICAL"
