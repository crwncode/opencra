# OpenCRA CLI

```text
opencra scan [TARGET]
  --format {table,json,cyclonedx,spdx}
  --output PATH
  --export-pdf PATH
  --fail-on {none,kev,critical,high}   (default: kev)
  --offline
  --enrich {none,nvd}
  --sync-cloud
  --syft-bin PATH
  --quiet / --verbose

opencra doctor
opencra doctor --install-syft
opencra kev refresh
opencra report --last --export-pdf PATH
```

`TARGET` may be a Syft scan target (directory, image, …) or an existing CycloneDX JSON file. Files with `"bomFormat": "CycloneDX"` are parsed directly and do not require Syft.

Directory and image scans need [Anchore Syft](https://github.com/anchore/syft). Resolution order: `--syft-bin` → `PATH` → managed `~/.opencra/bin/syft`. If Syft is missing and the scan is not `--offline`, OpenCRA downloads the official GitHub release once to `~/.opencra/bin` (HTTPS, User-Agent `opencra/<ver>`, 10s API timeout, 60s binary timeout, SHA-256 checksum). `--offline` never downloads; install via `brew install syft` or `opencra doctor --install-syft` while online.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Clean (or no threshold hit) |
| 1 | `--fail-on` threshold hit |
| 2 | Tool or config error (missing Syft, empty KEV cache in `--offline`, etc.) |

## Cache

State directory `~/.opencra` (override with `OPENCRA_HOME`). SQLite cache at `~/.opencra/cache.db` (override with `OPENCRA_CACHE`) using WAL mode. Managed Syft is `~/.opencra/bin/syft`. OSV results expire after 12 hours. KEV refreshes daily.

## PDF

`--export-pdf` uses WeasyPrint when Cairo and Pango are installed. Otherwise OpenCRA writes HTML and Markdown and explains how to install native libraries. The GitHub Action image includes those libraries.

## Cloud sync

After a scan, unless `--quiet`, the CLI prints a one-line completion summary. Table format writes it to stdout; `json` / `cyclonedx` / `spdx` write it to stderr so payloads stay parseable.

`--sync-cloud` POSTs the normalized scan JSON to `OPENCRA_API_URL` with `OPENCRA_API_KEY`. There is **no default commercial URL**. Both variables are required; otherwise the CLI reports that sync was skipped and leaves the local scan intact. A host-only value such as `http://127.0.0.1:8000` still receives `/v1/ingest` appended.

The public CLI does not depend on a hosted control plane. Downstream consumers can take [`packages/shared`](../packages/shared) as:

```toml
opencra-shared = { git = "https://github.com/crwncode/opencra.git", subdirectory = "packages/shared" }
```
