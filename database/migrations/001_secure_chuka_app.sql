create extension if not exists "pgcrypto";

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  full_name text not null,
  email text not null unique,
  role text not null check (role in ('student', 'lecturer', 'admin')),
  reg_number text unique,
  staff_number text unique,
  department text,
  phone text,
  bio text,
  avatar_url text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.chat_rooms (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  type text not null check (type in ('class', 'group', 'department')),
  course_code text,
  created_by uuid references public.profiles(id) on delete set null,
  updated_at timestamptz not null default now()
);

create table if not exists public.chat_room_members (
  id uuid primary key default gen_random_uuid(),
  room_id uuid not null references public.chat_rooms(id) on delete cascade,
  profile_id uuid not null references public.profiles(id) on delete cascade,
  member_role text not null default 'member' check (member_role in ('member', 'moderator', 'owner')),
  joined_at timestamptz not null default now(),
  unique (room_id, profile_id)
);

create table if not exists public.chat_messages (
  id uuid primary key default gen_random_uuid(),
  room_id uuid not null references public.chat_rooms(id) on delete cascade,
  sender_id uuid not null references public.profiles(id) on delete cascade,
  sender_name text not null,
  sender_role text not null check (sender_role in ('student', 'lecturer', 'admin')),
  message text not null,
  created_at timestamptz not null default now()
);

create table if not exists public.timetable_entries (
  id uuid primary key default gen_random_uuid(),
  audience text not null,
  day text not null,
  day_order int not null default 0,
  time text not null,
  title text not null,
  venue text not null,
  course_code text not null,
  lecturer text not null,
  status text not null default 'upcoming' check (status in ('upcoming', 'live', 'done')),
  created_at timestamptz not null default now()
);

create table if not exists public.announcements (
  id uuid primary key default gen_random_uuid(),
  title text not null,
  body text not null,
  audience text not null,
  author text not null,
  priority text not null default 'normal' check (priority in ('normal', 'high')),
  published_at timestamptz not null default now()
);

create table if not exists public.notes (
  id uuid primary key default gen_random_uuid(),
  title text not null,
  course_code text not null,
  author text not null,
  summary text not null,
  file_label text not null,
  storage_path text,
  uploaded_at timestamptz not null default now()
);

create table if not exists public.email_otp_challenges (
  id uuid primary key default gen_random_uuid(),
  email text not null,
  purpose text not null default 'registration',
  otp_hash text not null,
  request_ip text,
  user_agent text,
  attempt_count int not null default 0,
  max_attempts int not null default 5,
  expires_at timestamptz not null,
  verified_at timestamptz,
  consumed_at timestamptz,
  last_attempt_at timestamptz,
  created_at timestamptz not null default now()
);

create index if not exists idx_profiles_role on public.profiles(role);
create index if not exists idx_chat_room_members_room_profile on public.chat_room_members(room_id, profile_id);
create index if not exists idx_chat_messages_room_created on public.chat_messages(room_id, created_at desc);
create index if not exists idx_email_otp_email_purpose_created on public.email_otp_challenges(email, purpose, created_at desc);

create or replace function public.touch_updated_at()
returns trigger
language plpgsql
as $$
begin
  new.updated_at = now();
  return new;
end;
$$;

drop trigger if exists profiles_touch_updated_at on public.profiles;
create trigger profiles_touch_updated_at
before update on public.profiles
for each row execute function public.touch_updated_at();

create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  insert into public.profiles (
    id,
    full_name,
    email,
    role,
    reg_number,
    staff_number,
    department,
    phone,
    bio,
    avatar_url
  )
  values (
    new.id,
    coalesce(new.raw_user_meta_data->>'full_name', split_part(coalesce(new.email, ''), '@', 1)),
    new.email,
    coalesce(new.raw_user_meta_data->>'role', 'student'),
    nullif(new.raw_user_meta_data->>'reg_number', ''),
    nullif(new.raw_user_meta_data->>'staff_number', ''),
    nullif(new.raw_user_meta_data->>'department', ''),
    nullif(new.raw_user_meta_data->>'phone', ''),
    nullif(new.raw_user_meta_data->>'bio', ''),
    nullif(new.raw_user_meta_data->>'avatar_url', '')
  )
  on conflict (id) do update
  set
    full_name = excluded.full_name,
    email = excluded.email,
    role = excluded.role,
    reg_number = excluded.reg_number,
    staff_number = excluded.staff_number,
    department = excluded.department,
    phone = excluded.phone,
    bio = excluded.bio,
    avatar_url = excluded.avatar_url,
    updated_at = now();

  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
after insert on auth.users
for each row execute function public.handle_new_user();

alter table public.profiles enable row level security;
alter table public.chat_rooms enable row level security;
alter table public.chat_room_members enable row level security;
alter table public.chat_messages enable row level security;
alter table public.timetable_entries enable row level security;
alter table public.announcements enable row level security;
alter table public.notes enable row level security;
alter table public.email_otp_challenges enable row level security;

drop policy if exists "profiles read own only" on public.profiles;
create policy "profiles read own only"
on public.profiles
for select
to authenticated
using (
  auth.uid() = id
  or exists (
    select 1
    from public.profiles admin_profile
    where admin_profile.id = auth.uid()
      and admin_profile.role = 'admin'
  )
);

drop policy if exists "profiles update own only" on public.profiles;
create policy "profiles update own only"
on public.profiles
for update
to authenticated
using (
  auth.uid() = id
  or exists (
    select 1
    from public.profiles admin_profile
    where admin_profile.id = auth.uid()
      and admin_profile.role = 'admin'
  )
)
with check (
  auth.uid() = id
  or exists (
    select 1
    from public.profiles admin_profile
    where admin_profile.id = auth.uid()
      and admin_profile.role = 'admin'
  )
);

drop policy if exists "profiles insert own row" on public.profiles;
create policy "profiles insert own row"
on public.profiles
for insert
to authenticated
with check (auth.uid() = id);

drop policy if exists "chat rooms visible to members" on public.chat_rooms;
create policy "chat rooms visible to members"
on public.chat_rooms
for select
to authenticated
using (
  exists (
    select 1
    from public.chat_room_members m
    where m.room_id = chat_rooms.id
      and m.profile_id = auth.uid()
  )
  or exists (
    select 1
    from public.profiles p
    where p.id = auth.uid()
      and p.role = 'admin'
  )
);

drop policy if exists "chat rooms created by owner" on public.chat_rooms;
create policy "chat rooms created by owner"
on public.chat_rooms
for insert
to authenticated
with check (created_by = auth.uid());

drop policy if exists "chat room members visible by member" on public.chat_room_members;
create policy "chat room members visible by member"
on public.chat_room_members
for select
to authenticated
using (
  profile_id = auth.uid()
  or exists (
    select 1
    from public.chat_room_members own_member
    where own_member.room_id = chat_room_members.room_id
      and own_member.profile_id = auth.uid()
  )
  or exists (
    select 1
    from public.profiles p
    where p.id = auth.uid()
      and p.role = 'admin'
  )
);

drop policy if exists "chat room members inserted by owner" on public.chat_room_members;
create policy "chat room members inserted by owner"
on public.chat_room_members
for insert
to authenticated
with check (
  exists (
    select 1
    from public.chat_room_members own_member
    where own_member.room_id = chat_room_members.room_id
      and own_member.profile_id = auth.uid()
      and own_member.member_role in ('owner', 'moderator')
  )
  or exists (
    select 1
    from public.profiles p
    where p.id = auth.uid()
      and p.role = 'admin'
  )
);

drop policy if exists "chat messages visible to room members" on public.chat_messages;
create policy "chat messages visible to room members"
on public.chat_messages
for select
to authenticated
using (
  exists (
    select 1
    from public.chat_room_members m
    where m.room_id = chat_messages.room_id
      and m.profile_id = auth.uid()
  )
  or exists (
    select 1
    from public.profiles p
    where p.id = auth.uid()
      and p.role = 'admin'
  )
);

drop policy if exists "chat messages inserted by room members" on public.chat_messages;
create policy "chat messages inserted by room members"
on public.chat_messages
for insert
to authenticated
with check (
  sender_id = auth.uid()
  and exists (
    select 1
    from public.chat_room_members m
    where m.room_id = chat_messages.room_id
      and m.profile_id = auth.uid()
  )
);

drop policy if exists "timetable visible to authenticated" on public.timetable_entries;
create policy "timetable visible to authenticated"
on public.timetable_entries
for select
to authenticated
using (true);

drop policy if exists "announcements visible to authenticated" on public.announcements;
create policy "announcements visible to authenticated"
on public.announcements
for select
to authenticated
using (true);

drop policy if exists "notes visible to authenticated" on public.notes;
create policy "notes visible to authenticated"
on public.notes
for select
to authenticated
using (true);

revoke all on public.email_otp_challenges from anon;
revoke all on public.email_otp_challenges from authenticated;

do $$
begin
  if not exists (
    select 1
    from pg_publication_tables
    where pubname = 'supabase_realtime'
      and schemaname = 'public'
      and tablename = 'chat_messages'
  ) then
    alter publication supabase_realtime add table public.chat_messages;
  end if;

  if not exists (
    select 1
    from pg_publication_tables
    where pubname = 'supabase_realtime'
      and schemaname = 'public'
      and tablename = 'chat_rooms'
  ) then
    alter publication supabase_realtime add table public.chat_rooms;
  end if;
end $$;
