-- Multi-tenant schema. RLS is the tenant boundary.
create extension if not exists "pgcrypto";

create table if not exists organizations (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  slug text not null unique,
  main_establishment_ms text,
  designated_csirt text,
  sso_enabled boolean not null default false,
  created_at timestamptz not null default now()
);

create table if not exists memberships (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references organizations(id) on delete cascade,
  user_id uuid not null,
  email text,
  role text not null check (role in ('owner', 'admin', 'compliance_officer', 'engineer')),
  created_at timestamptz not null default now(),
  unique (org_id, user_id)
);

create table if not exists products (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references organizations(id) on delete cascade,
  name text not null,
  version text,
  market_member_states text[] not null default '{}',
  created_at timestamptz not null default now()
);

create table if not exists sboms (
  id uuid primary key default gen_random_uuid(),
  product_id uuid not null references products(id) on delete cascade,
  org_id uuid not null references organizations(id) on delete cascade,
  document jsonb not null,
  git_sha text,
  source text not null default 'cli',
  serial_number text,
  created_at timestamptz not null default now()
);

create table if not exists components (
  id uuid primary key default gen_random_uuid(),
  sbom_id uuid not null references sboms(id) on delete cascade,
  org_id uuid not null references organizations(id) on delete cascade,
  purl text,
  name text not null,
  version text
);

create table if not exists vuln_matches (
  id uuid primary key default gen_random_uuid(),
  component_id uuid references components(id) on delete set null,
  org_id uuid not null references organizations(id) on delete cascade,
  product_id uuid references products(id) on delete cascade,
  purl text not null,
  osv_id text,
  cve_id text,
  severity text,
  cvss_v3 double precision,
  epss double precision,
  in_kev boolean not null default false,
  kev_added_at timestamptz,
  status text not null default 'open',
  vex_status text,
  summary text,
  created_at timestamptz not null default now()
);

create table if not exists cra_cases (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references organizations(id) on delete cascade,
  product_id uuid not null references products(id) on delete cascade,
  match_id uuid references vuln_matches(id) on delete set null,
  case_type text not null check (case_type in ('actively_exploited_vuln', 'severe_incident')),
  status text not null default 'candidate',
  awareness_at timestamptz,
  fix_available_at timestamptz,
  early_warning_submitted_at timestamptz,
  notification_submitted_at timestamptz,
  final_submitted_at timestamptz,
  srp_reference_id text,
  sensitivity text,
  exploit_nature text,
  corrective_measures text,
  created_at timestamptz not null default now()
);

create table if not exists audit_events (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references organizations(id) on delete cascade,
  case_id uuid references cra_cases(id) on delete cascade,
  actor_id text not null,
  action text not null,
  payload jsonb not null default '{}',
  prev_hash text,
  event_hash text not null,
  created_at timestamptz not null default now()
);

create table if not exists vex_statements (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references organizations(id) on delete cascade,
  product_id uuid references products(id) on delete cascade,
  document jsonb not null,
  created_at timestamptz not null default now()
);

create table if not exists subscriptions (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null unique references organizations(id) on delete cascade,
  tier text not null default 'community'
    check (tier in ('community', 'pro', 'pro_plus', 'enterprise')),
  status text not null default 'active',
  seat_limit integer not null default 1,
  product_limit integer not null default 1,
  stripe_customer_id text,
  stripe_subscription_id text,
  retention_days integer not null default 7
);

create table if not exists api_keys (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references organizations(id) on delete cascade,
  name text not null default 'cli',
  token_hash text not null unique,
  created_at timestamptz not null default now()
);

-- Helper: current JWT claims. Supabase injects auth.uid(); we also accept
-- request.jwt.claim.org_id set by the API for service-role paths.
create or replace function public.current_org_ids()
returns setof uuid
language sql
stable
as $$
  select org_id from memberships where user_id = auth.uid()
$$;

alter table organizations enable row level security;
alter table memberships enable row level security;
alter table products enable row level security;
alter table sboms enable row level security;
alter table components enable row level security;
alter table vuln_matches enable row level security;
alter table cra_cases enable row level security;
alter table audit_events enable row level security;
alter table vex_statements enable row level security;
alter table subscriptions enable row level security;
alter table api_keys enable row level security;

create policy org_select on organizations
  for select using (id in (select public.current_org_ids()));
create policy membership_select on memberships
  for select using (org_id in (select public.current_org_ids()));
create policy product_all on products
  using (org_id in (select public.current_org_ids()));
create policy sbom_all on sboms
  using (org_id in (select public.current_org_ids()));
create policy component_all on components
  using (org_id in (select public.current_org_ids()));
create policy match_all on vuln_matches
  using (org_id in (select public.current_org_ids()));
create policy case_all on cra_cases
  using (org_id in (select public.current_org_ids()));
create policy audit_select on audit_events
  for select using (org_id in (select public.current_org_ids()));
create policy audit_insert on audit_events
  for insert with check (org_id in (select public.current_org_ids()));
create policy vex_all on vex_statements
  using (org_id in (select public.current_org_ids()));
create policy sub_select on subscriptions
  for select using (org_id in (select public.current_org_ids()));
create policy keys_all on api_keys
  using (org_id in (select public.current_org_ids()));

-- Audit events are append-only: no update/delete policies on purpose.
