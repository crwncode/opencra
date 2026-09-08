# Supabase

1. Create a project (EU region for residency).
2. Run `migrations/0001_init.sql` in the SQL editor (or `supabase db push` if using the CLI).
3. Enable Email + GitHub Auth. Enterprise SSO uses Supabase SAML/OIDC.
4. Copy URL, anon key, and JWT secret into `.env` (see repo `.env.example`).

Row Level Security scopes every table to `memberships.user_id = auth.uid()`. The FastAPI service additionally filters by `org_id` and accepts hashed CLI API keys.
