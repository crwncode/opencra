# OpenCRA GitHub Action

Add CRA checks with three lines of YAML. Published from the root of [`crwncode/opencra`](https://github.com/crwncode/opencra) — search **OpenCRA** on the GitHub Marketplace.

```yaml
- uses: crwncode/opencra@v1
  with:
    fail-on-cve: true
```

That fails the job on a CISA KEV hit (an actively exploited CVE). Equivalent to `fail-on: kev`.

## Inputs

| Input | Default | Meaning |
|---|---|---|
| `target` | `.` | Directory, container image, or CycloneDX JSON |
| `fail-on` | `kev` | `none` \| `kev` \| `critical` \| `high` |
| `fail-on-cve` | `false` | When `true`, fail on CISA KEV hits |
| `format` | `table` | `table` \| `json` \| `cyclonedx` \| `spdx` |
| `export-pdf` | | Community PDF path (HTML fallback if Cairo/Pango are missing) |
| `offline` | `false` | Cached KEV/OSV only |
| `sync-cloud` | `false` | POST to CRA-Shield (`OPENCRA_API_KEY`) |
| `syft-version` | `v1.18.1` | Syft release to install when missing |

The composite action installs Python 3.12 and Syft if needed, then runs `opencra scan`. A Docker image in this folder installs Cairo and Pango so `--export-pdf` works headless.
