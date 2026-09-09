from pathlib import Path

from opencra_cli.syft import (
    format_syft_label,
    load_cyclonedx_file,
    parse_syft_version,
    version_ok,
)

SAMPLE_CDX = Path(__file__).resolve().parents[1] / "examples" / "sample.cdx.json"

SYFT_VERSION_BLOCK = """
Application:   syft
Version:       1.51.1
BuildDate:     2026-08-27T16:55:02Z
GitDescription: v1.51.1
SchemaVersion: 16.1.10
""".strip()


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
