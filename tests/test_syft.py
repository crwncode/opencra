from opencra_cli.syft import parse_syft_version, version_ok


def test_parse_syft_version() -> None:
    assert parse_syft_version("syft 1.18.1") == (1, 18, 1)
    assert parse_syft_version("1.0.0") == (1, 0, 0)


def test_min_version() -> None:
    assert version_ok((1, 0, 0))
    assert not version_ok((0, 9, 0))
