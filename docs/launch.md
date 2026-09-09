# Launch kit — get OpenCRA in front of developers

Copy, paste, post. Do not over-claim: a KEV hit is a **candidate**, not legal awareness. OpenCRA does not file with ENISA and is not a notified body.

## Repo settings (GitHub UI — needs owner login)

`gh` is not authenticated in this workspace. Do these once in the browser:

1. **Description:** `Open-source EU Cyber Resilience Act CLI — SBOM + CISA KEV in one command`
2. **Website:** `https://github.com/crwncode/opencra` (do not set a commercial domain until you own one)
3. **Topics:** `cra`, `cyber-resilience-act`, `sbom`, `cyclonedx`, `cisa-kev`, `osv`, `devsecops`, `github-action`, `python`, `compliance`
4. **Social preview:** repo Settings → General → Social preview → upload `docs/assets/opencra-scan.svg` (or a PNG export of it)
5. **GitHub Marketplace:** repo → Action → *Draft a new release* is already tagged `v1`. Open [Publish your Action to the Marketplace](https://docs.github.com/en/actions/sharing-automations/publishing-actions-in-github-marketplace) and list **OpenCRA** from root `action.yml`. Primary usage string:

   ```yaml
   - uses: crwncode/opencra@v1
     with:
       fail-on-cve: true
   ```

   A separate `crwncode/opencra-action` alias repo is optional later. `crwncode/opencra@v1` already works and is what Marketplace expects when the action lives in this repo.

6. **Discussions:** enable GitHub Discussions (Q&A + Show and tell).
7. **Push `main`:** keep `main` current before you post. Tag a release only after the PyPI version you want is on `main`.

---

## Show HN

**Title:** Show HN: OpenCRA – open-source EU Cyber Resilience Act CLI for developers

**Text:**

```text
CRA Article 14 reporting starts 11 September 2026. European vendors suddenly
need an SBOM, a way to know which CVEs are actively exploited, and a 24h/72h
clock — without buying a GRC platform first.

I built OpenCRA as a local-first CLI + GitHub Action:

    uvx opencra scan .

It wraps Syft (or an existing CycloneDX file), queries OSV, and flags CISA KEV
hits. Those are the findings that *may* start a 24-hour CRA clock after a human
becomes aware. A scanner match is a candidate, not legal awareness — we do not
auto-file with ENISA and we do not claim CE marking.

GitHub Action (3 lines):

    - uses: crwncode/opencra@v1
      with:
        fail-on-cve: true

Free locally. Optional --sync-cloud posts to an ingest URL you configure
(OPENCRA_API_URL + OPENCRA_API_KEY). There is no default commercial host.

https://github.com/crwncode/opencra
```

Post at https://news.ycombinator.com/submit — weekday morning US East / afternoon CET. Reply to every comment in the first two hours.

---

## Reddit

Keep each post in your own words if the subreddit forbids copy-paste marketing. Lead with the problem, not the product.

### r/devops · r/devsecops

**Title:** Open-source CLI that maps your SBOM PURLs to CISA KEV for EU CRA Article 14

```text
Article 14 reporting starts 11 September 2026. We got tired of stitching Syft
+ Grype + a spreadsheet to answer “would this start a 24h CRA clock?”

OpenCRA is Apache-2.0:

- Syft (or bring your own CycloneDX)
- OSV batch query
- CISA KEV match on the CVE
- GitHub Action: uses: crwncode/opencra@v1 / fail-on-cve: true

A KEV hit is a candidate. Clocks start after human awareness — the tool does
not file with ENISA.

Repo: https://github.com/crwncode/opencra
```

### r/python

**Title:** OpenCRA — `uvx opencra scan .` for EU Cyber Resilience Act / CISA KEV

```text
Python 3.12 CLI. pipx / uvx / PyPI (`opencra`). Wraps Syft, matches OSV + the
CISA Known Exploited Vulnerabilities catalog, fails CI on KEV by default.

Built because CRA Article 14 is a developer problem, not just a GRC problem.

https://github.com/crwncode/opencra
```

### r/rust · r/golang · r/node

Short version: Syft already speaks Cargo/Go/npm. OpenCRA is the KEV/CRA layer on top. Same Action YAML. Link the repo. Do not dump the same essay in every language sub.

### r/cybersecurity · r/netsec

Lead with the legal-clock caveat in the first paragraph or you will get torn apart. Same link.

### EU / local

- r/thenetherlands, r/de, r/ireland, r/belgium — one sentence in the local language, English body, repo link.
- Dutch: “Open-source CLI die je SBOM koppelt aan CISA KEV voor de EU Cyber Resilience Act.”
- German: “Open-Source-CLI: SBOM gegen CISA KEV prüfen — relevant für den Cyber Resilience Act.”

---

## X / LinkedIn (keep under 500 characters for X)

```text
CRA Article 14 starts 11 Sep 2026.

uvx opencra scan .

Open-source CLI + GitHub Action: SBOM → OSV → CISA KEV. Know which vulns may
start a 24h clock — locally, no account.

https://github.com/crwncode/opencra
```

LinkedIn: add one sentence on why you built it (European vendors were bolting scanners onto spreadsheets) and a screenshot of the README demo.

---

## What not to say

- Do not say OpenCRA “makes you CRA compliant.”
- Do not say a scan “starts the 24-hour clock.”
- Do not say it files with ENISA or replaces a notified body.
