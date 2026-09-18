-- ============================================================
-- Pulse Control Panel — FULL SCHEMA FIX (run once in Supabase)
-- SQL Editor → New query → Paste all → Run
-- ============================================================

-- ---------- app_config (live update channel) ----------
create table if not exists app_config (
  id int primary key default 1 check (id = 1),
  version text default '1.0.0',
  download_url text default '',
  sha256 text default '',
  release_date text default '',
  changelog text default '',
  maintenance_tweaks jsonb default '[]'::jsonb,
  file_size bigint default 0,
  mandatory boolean default true,
  updated_at timestamptz default now()
);

alter table app_config add column if not exists version text default '1.0.0';
alter table app_config add column if not exists download_url text default '';
alter table app_config add column if not exists sha256 text default '';
alter table app_config add column if not exists release_date text default '';
alter table app_config add column if not exists changelog text default '';
alter table app_config add column if not exists maintenance_tweaks jsonb default '[]'::jsonb;
alter table app_config add column if not exists file_size bigint default 0;
alter table app_config add column if not exists mandatory boolean default true;
alter table app_config add column if not exists updated_at timestamptz default now();

insert into app_config (id) values (1)
on conflict (id) do nothing;

-- ---------- license_keys ----------
create table if not exists license_keys (
  key text primary key,
  duration_days int default 30,
  is_activated boolean default false,
  activated_at double precision,
  expires_at double precision,
  is_frozen boolean default false,
  freeze_count int default 0,
  frozen_remaining_seconds int default 0,
  last_frozen_at double precision,
  last_unfrozen_at double precision,
  username text default '',
  bound_hwid text default '',
  bound_serials jsonb default '[]'::jsonb,
  bound_ip text default '',
  created_at text default '',
  revoked boolean default false
);

alter table license_keys add column if not exists duration_days int default 30;
alter table license_keys add column if not exists is_activated boolean default false;
alter table license_keys add column if not exists activated_at double precision;
alter table license_keys add column if not exists expires_at double precision;
alter table license_keys add column if not exists is_frozen boolean default false;
alter table license_keys add column if not exists freeze_count int default 0;
alter table license_keys add column if not exists frozen_remaining_seconds int default 0;
alter table license_keys add column if not exists last_frozen_at double precision;
alter table license_keys add column if not exists last_unfrozen_at double precision;
alter table license_keys add column if not exists username text default '';
alter table license_keys add column if not exists bound_hwid text default '';
alter table license_keys add column if not exists bound_serials jsonb default '[]'::jsonb;
alter table license_keys add column if not exists bound_ip text default '';
alter table license_keys add column if not exists created_at text default '';
alter table license_keys add column if not exists revoked boolean default false;

-- ---------- banned ----------
create table if not exists banned (
  id int primary key default 1 check (id = 1),
  hwids jsonb default '[]'::jsonb,
  serials jsonb default '[]'::jsonb,
  ips jsonb default '[]'::jsonb
);

alter table banned add column if not exists hwids jsonb default '[]'::jsonb;
alter table banned add column if not exists serials jsonb default '[]'::jsonb;
alter table banned add column if not exists ips jsonb default '[]'::jsonb;

insert into banned (id) values (1)
on conflict (id) do nothing;

-- ---------- admin_sessions ----------
create table if not exists admin_sessions (
  token text primary key,
  username text not null,
  created_at double precision not null,
  expires_at double precision not null,
  ip text default ''
);

alter table admin_sessions add column if not exists username text;
alter table admin_sessions add column if not exists created_at double precision;
alter table admin_sessions add column if not exists expires_at double precision;
alter table admin_sessions add column if not exists ip text default '';

-- ---------- login_attempts ----------
create table if not exists login_attempts (
  ip text primary key,
  fails int default 0,
  locked_until double precision default 0
);

alter table login_attempts add column if not exists fails int default 0;
alter table login_attempts add column if not exists locked_until double precision default 0;

-- ---------- user_logs ----------
create table if not exists user_logs (
  id bigserial primary key,
  key text not null,
  timestamp text default '',
  username text default '',
  action text default '',
  details text default '',
  created_at timestamptz default now()
);

alter table user_logs add column if not exists key text;
alter table user_logs add column if not exists timestamp text default '';
alter table user_logs add column if not exists username text default '';
alter table user_logs add column if not exists action text default '';
alter table user_logs add column if not exists details text default '';
alter table user_logs add column if not exists created_at timestamptz default now();

create index if not exists user_logs_key_idx on user_logs (key);

-- ---------- release_history (rollback channel) ----------
create table if not exists release_history (
  id bigserial primary key,
  version text not null,
  download_url text default '',
  sha256 text default '',
  release_date text default '',
  changelog text default '',
  file_name text default '',
  file_size bigint default 0,
  is_active boolean default false,
  created_at timestamptz default now()
);

alter table release_history add column if not exists version text;
alter table release_history add column if not exists download_url text default '';
alter table release_history add column if not exists sha256 text default '';
alter table release_history add column if not exists release_date text default '';
alter table release_history add column if not exists changelog text default '';
alter table release_history add column if not exists file_name text default '';
alter table release_history add column if not exists file_size bigint default 0;
alter table release_history add column if not exists is_active boolean default false;
alter table release_history add column if not exists created_at timestamptz default now();

create index if not exists release_history_version_idx on release_history (version);
create index if not exists release_history_created_idx on release_history (created_at desc);

-- ---------- RLS (service role bypasses; keeps anon out) ----------
alter table app_config enable row level security;
alter table license_keys enable row level security;
alter table banned enable row level security;
alter table admin_sessions enable row level security;
alter table login_attempts enable row level security;
alter table user_logs enable row level security;
alter table release_history enable row level security;

-- ---------- panel_settings (storage caps, etc.) ----------
create table if not exists panel_settings (
  id int primary key default 1 check (id = 1),
  soft_cap_bytes bigint default 524288000,
  warn_bytes bigint default 419430400,
  crit_bytes bigint default 503316480,
  warn_count int default 8,
  crit_count int default 12,
  updated_at timestamptz default now()
);

alter table panel_settings add column if not exists soft_cap_bytes bigint default 524288000;
alter table panel_settings add column if not exists warn_bytes bigint default 419430400;
alter table panel_settings add column if not exists crit_bytes bigint default 503316480;
alter table panel_settings add column if not exists warn_count int default 8;
alter table panel_settings add column if not exists crit_count int default 12;
alter table panel_settings add column if not exists updated_at timestamptz default now();

insert into panel_settings (id) values (1)
on conflict (id) do nothing;

alter table panel_settings enable row level security;

-- ---------- Refresh PostgREST schema cache ----------
notify pgrst, 'reload schema';

-- Done.
-- REQUIRED STORAGE SETUP (Dashboard → Storage):
--   1. Create a PUBLIC bucket named exactly: releases
--   2. Storage → Configuration → add your Vercel domain to allowed CORS origins
--      (or * during first deploy), methods: GET, PUT, POST, HEAD
--   3. Confirm RLS is enabled on all tables above (service role bypasses RLS)
