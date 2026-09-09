# Optional local control plane

In-repo FastAPI + web apps for local clocks, audit PDFs, OpenVEX, and SRP packets. Not a hosted product and not required for CLI scans.

## Run locally

```bash
uv sync --all-packages --group dev
uv run uvicorn opencra_api.main:app --app-dir apps/api --reload
cd apps/web && npm install && npm run dev
```

Dev auth headers: `X-Dev-User-Id` and `X-Dev-Org-Id`. Production uses Supabase JWT (`Authorization: Bearer`) or a hashed CLI API key.

Apply [`supabase/migrations/0001_init.sql`](../supabase/migrations/0001_init.sql) to a Supabase project and set `DATABASE_URL` / `SUPABASE_JWT_SECRET`.

CLI `--sync-cloud` POSTs to `$OPENCRA_API_URL/v1/ingest` only when you set both `OPENCRA_API_URL` and `OPENCRA_API_KEY`. There is no default commercial host.

## Endpoints

| Method | Path | Notes |
|---|---|---|
| POST | `/v1/ingest` | CLI `--sync-cloud` |
| GET/POST | `/products` | Workspace products |
| GET | `/matches` | Vulnerability timeline |
| GET/PATCH | `/cases` | Acknowledge, submit stages, set fix |
| GET | `/cases/{id}/srp/{stage}` | SRP pack (Pro Plus+) — does not file |
| GET | `/products/{id}/audit-report` | Formal audit PDF (Pro+) |
| GET | `/audit` `/audit/export` | Hash-chained log (export is Enterprise) |
| POST | `/vex` | OpenVEX import; candidates dismiss; acknowledged cases need override |
| POST | `/billing/checkout` `/billing/webhook` | Stripe |
| GET/POST | `/org/sso` | Enterprise SAML/OIDC flag |

## Legal

Awareness is a checkbox with legal copy. KEV ingest creates `candidate` rows with `awareness_at = null`. The `SrpAdapter` default is `PortalOnlyAdapter`.
