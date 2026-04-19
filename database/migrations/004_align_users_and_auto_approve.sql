create extension if not exists pgcrypto;

alter table public.users
add column if not exists reg_number text,
add column if not exists full_name text,
add column if not exists phone text,
add column if not exists department text,
add column if not exists staff_number text,
add column if not exists bio text,
add column if not exists avatar_url text,
add column if not exists password_reset_required boolean not null default false;

create unique index if not exists users_reg_number_uidx
  on public.users (reg_number)
  where reg_number is not null and reg_number <> '';

update public.users u
set
  reg_number = coalesce(nullif(u.reg_number, ''), nullif(s.admission_number, ''), nullif(s.reg_number, '')),
  full_name = coalesce(nullif(u.full_name, ''), nullif(s.full_name, '')),
  phone = coalesce(nullif(u.phone, ''), nullif(s.phone, '')),
  department = coalesce(nullif(u.department, ''), nullif(s.address, '')),
  bio = coalesce(nullif(u.bio, ''), nullif(s.bio, '')),
  avatar_url = coalesce(nullif(u.avatar_url, ''), nullif(s.profile_picture_url, ''))
from public.students s
where u.id = s.user_id;

update public.users u
set
  reg_number = coalesce(nullif(u.reg_number, ''), nullif(t.teacher_number, ''), nullif(t.reg_number, '')),
  full_name = coalesce(nullif(u.full_name, ''), nullif(t.full_name, '')),
  phone = coalesce(nullif(u.phone, ''), nullif(t.phone, '')),
  department = coalesce(nullif(u.department, ''), nullif(t.subject, '')),
  staff_number = coalesce(nullif(u.staff_number, ''), nullif(t.teacher_number, ''), nullif(t.reg_number, '')),
  bio = coalesce(nullif(u.bio, ''), nullif(t.bio, '')),
  avatar_url = coalesce(nullif(u.avatar_url, ''), nullif(t.profile_picture_url, ''))
from public.teachers t
where u.id = t.user_id;

update public.users u
set
  full_name = coalesce(nullif(u.full_name, ''), nullif(a.full_name, '')),
  phone = coalesce(nullif(u.phone, ''), nullif(a.phone, '')),
  bio = coalesce(nullif(u.bio, ''), nullif(a.bio, '')),
  avatar_url = coalesce(nullif(u.avatar_url, ''), nullif(a.profile_picture_url, ''))
from public.admins a
where u.id = a.user_id;

update public.users
set password_reset_required = false
where password_hash ~ '^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$';

alter table public.registration
alter column approved set default true;

update public.registration
set approved = true,
    approved_at = coalesce(approved_at, now())
where approved is distinct from true;
