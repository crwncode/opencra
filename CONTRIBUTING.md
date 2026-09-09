# Contributing to OpenCRA

Thank you for helping EU software vendors prepare for CRA Article 14 reporting.

## Development

```bash
uv sync --all-packages
uv run pytest
uv run ruff check packages tests
uv run mypy packages/shared/opencra_shared packages/cli/opencra_cli
```

## Good first issues

- Sample SBOMs in `examples/`
- Richer SPDX export in `packages/shared/opencra_shared/sbom.py`

## Rules

- Never start Article 14 clocks from a scanner match. `awareness_at` is human-set only.
- Never call a fictional ENISA API. SRP packets are human-in-the-loop.
- Syft is invoked with an argument array. Do not use `shell=True`.
- Validate PURLs with `packageurl-python` before OSV batch queries.

Discuss ideas in GitHub Discussions. OpenCRA is Apache 2.0. The CRA-Shield control plane lives in the private `opencra-cloud` repo.

Launch copy (Show HN, Reddit, Marketplace checklist) lives in [docs/launch.md](docs/launch.md).
