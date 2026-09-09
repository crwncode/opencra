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

`examples/sample.cdx.json` is a clean-ish SBOM (`requests`). `examples/sample-kev.cdx.json` is Log4j 2.14.1 so `--fail-on kev` exits 1. A KEV hit is a **candidate**, never awareness.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Clean (or no threshold hit) |
| 1 | `--fail-on` threshold hit |
| 2 | Tool or config error (missing Syft, empty KEV cache in `--offline`, etc.) |

## Cache

SQLite at `~/.opencra/cache.db` (override with `OPENCRA_CACHE`) using WAL mode. OSV results expire after 12 hours. KEV refreshes daily.

## PDF

`--export-pdf` uses WeasyPrint when the `opencra-cli[pdf]` extra and Cairo/Pango are installed (`pip install 'opencra-cli[pdf]'`). Otherwise OpenCRA writes HTML and Markdown and explains how to install native libraries. The GitHub Action Docker image in `packages/action/` includes those libraries; the composite Action falls back to HTML.

## Cloud sync

`--sync-cloud` POSTs the scan to `OPENCRA_API_URL` (default `https://api.crashield.dev`) with `OPENCRA_API_KEY`. Without a key, the CLI prints a signup URL and leaves the local scan intact.
