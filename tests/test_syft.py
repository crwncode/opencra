from pathlib import Path

from opencra_cli.syft import load_cyclonedx_file, parse_syft_version, version_ok

SAMPLE_CDX = Path(__file__).resolve().parents[1] / "examples" / "sample.cdx.json"


def test_parse_syft_version() -> None:
    assert parse_syft_version("syft 1.18.1") == (1, 18, 1)
    assert parse_syft_version("1.0.0") == (1, 0, 0)


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
