-- Pulse Control Panel — Supabase schema
-- Run this in the Supabase SQL Editor before deploying.

create table if not exists app_config (
  id int primary key default 1 check (id = 1),
  version text default '2.1.1',
  download_url text default '',
  sha256 text default '',
  release_date text default '',
  changelog text default '',
  maintenance_tweaks jsonb default '[]'::jsonb,
  updated_at timestamptz default now()
);

insert into app_config (id) values (1)
on conflict (id) do nothing;

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

create table if not exists banned (
  id int primary key default 1 check (id = 1),
  hwids jsonb default '[]'::jsonb,
  serials jsonb default '[]'::jsonb,
  ips jsonb default '[]'::jsonb
);

insert into banned (id) values (1)
on conflict (id) do nothing;

create table if not exists admin_sessions (
  token text primary key,
  username text not null,
  created_at double precision not null,
  expires_at double precision not null,
  ip text default ''
);

create table if not exists login_attempts (
  ip text primary key,
  fails int default 0,
  locked_until double precision default 0
);

create table if not exists user_logs (
  id bigserial primary key,
  key text not null,
  timestamp text default '',
  username text default '',
  action text default '',
  details text default '',
  created_at timestamptz default now()
);

create index if not exists user_logs_key_idx on user_logs (key);

-- Storage bucket for release binaries (create via Dashboard if SQL fails)
-- Dashboard → Storage → New bucket → name: releases → Public: ON

alter table app_config enable row level security;
alter table license_keys enable row level security;
alter table banned enable row level security;
alter table admin_sessions enable row level security;
alter table login_attempts enable row level security;
alter table user_logs enable row level security;

-- No public policies — only the service role key (server-side) can access data.
