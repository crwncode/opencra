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
opencra kev refresh
opencra report --last --export-pdf PATH
```

`TARGET` may be a Syft scan target (directory, image, …) or an existing CycloneDX JSON file. Files with `"bomFormat": "CycloneDX"` are parsed directly and do not require Syft.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Clean (or no threshold hit) |
| 1 | `--fail-on` threshold hit |
| 2 | Tool or config error (missing Syft, empty KEV cache in `--offline`, etc.) |

## Cache

SQLite at `~/.opencra/cache.db` (override with `OPENCRA_CACHE`) using WAL mode. OSV results expire after 12 hours. KEV refreshes daily.

## PDF

`--export-pdf` uses WeasyPrint when Cairo and Pango are installed. Otherwise OpenCRA writes HTML and Markdown and explains how to install native libraries. The GitHub Action image includes those libraries.

## Cloud sync

`--sync-cloud` POSTs the scan to `OPENCRA_API_URL` (default `https://api.crashield.dev`) with `OPENCRA_API_KEY`. Without a key, the CLI prints a signup URL and leaves the local scan intact.
