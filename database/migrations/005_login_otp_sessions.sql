create extension if not exists pgcrypto;

create table if not exists public.login_otp_sessions (
  id uuid primary key,
  email text not null,
  token text not null,
  refresh_token text not null,
  user_payload jsonb not null,
  created_at timestamptz not null default now(),
  expires_at timestamptz not null,
  consumed_at timestamptz
);

create index if not exists idx_login_otp_sessions_email_created
  on public.login_otp_sessions (email, created_at desc);

create index if not exists idx_login_otp_sessions_expires_at
  on public.login_otp_sessions (expires_at);

create index if not exists idx_login_otp_sessions_consumed_at
  on public.login_otp_sessions (consumed_at);
