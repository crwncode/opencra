# OpenCRA

**CRA Article 14 reporting starts 11 September 2026.** Know if you have a CISA KEV hit in one command.

OpenCRA is the open-source CLI and GitHub Action for Software Bills of Materials and actively-exploited vulnerability candidates. [CRA-Shield](https://crashield.dev) is the optional hosted control plane for team workspaces, the 24-hour awareness clock, and SRP-ready evidence packs.

A scanner hit is a **candidate**, never legal awareness. Article 14 clocks start only after a human assessment. OpenCRA does not file with ENISA, does not claim CE marking, and is not a notified body.

```bash
uvx opencra scan .
```

## Why not just Syft or Grype?

| Tool | What it does |
|---|---|
| Syft | Generates an SBOM |
| Grype / osv-scanner | Finds known CVEs |
| **OpenCRA** | Tells you which findings are **CISA KEV** hits — the ones that *may* start a 24-hour CRA clock after you become aware |

## Install

```bash
# Requires Anchore Syft on PATH
brew install syft          # macOS
# Linux: https://github.com/anchore/syft#installation

pipx install opencra
# or run without installing:
uvx opencra doctor
uvx opencra scan .
```

## Quickstart

```bash
opencra doctor
opencra kev refresh
opencra scan . --fail-on kev
opencra scan . --format cyclonedx --output sbom.cdx.json
opencra scan . --export-pdf cra-report.pdf
opencra report --last
# Demo a KEV candidate (exit 1). Not legal awareness; do not auto-file.
opencra scan examples/sample-kev.cdx.json --fail-on kev
```

### GitHub Action

```yaml
- uses: crwncode/opencra@v1
  with:
    fail-on: kev
```

## Legal disclaimer

OpenCRA prepares evidence and highlights Known Exploited Vulnerabilities. It does **not**:

- start the Article 14 legal clock automatically
- file notifications on the ENISA Single Reporting Platform
- certify CRA compliance or CE marking

The 24-hour early warning and 72-hour notification run from **awareness**. The 14-day final report for actively exploited vulnerabilities runs from when a **corrective measure is available**, not from detection. Severe incidents have a one-month final report after the 72-hour notification.

## CRA-Shield (optional hosted control plane)

```bash
uv sync --all-packages --group dev
uv run uvicorn opencra_api.main:app --app-dir apps/api --reload
cd apps/web && npm install && npm run dev
```

See [docs/saas.md](docs/saas.md). `--sync-cloud` on the CLI posts scans to `/v1/ingest`.

## Open core

The CLI, Action, Syft wrapper, OSV + KEV matching, and local reports are Apache 2.0. CRA-Shield (hosted clocks, audit trail, SRP packs, SSO) is commercial. See [docs/cli.md](docs/cli.md).

## License

Apache License 2.0. Copyright 2026 CodeLancaster.
