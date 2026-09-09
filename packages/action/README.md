# OpenCRA GitHub Action

```yaml
- uses: crwncode/opencra@v1
  with:
    target: .
    fail-on: kev
    export-pdf: cra-report.pdf
```

The composite action installs Syft if needed and runs `opencra scan`. A Docker image in this folder installs Cairo and Pango so `--export-pdf` works headless.
