-- QuantumForge cloud messaging schema (global usernames + passkey sign-in).
-- Run in Supabase: Dashboard -> SQL Editor -> New query -> paste -> Run. Safe to re-run.

create table if not exists public.profiles (
  username     text primary key
               check (username = lower(username) and username ~ '^[a-z0-9_.-]{3,32}$'),
  display_name text not null check (char_length(display_name) <= 32),
  public_key   jsonb not null
               check (public_key->>'kty' = 'RSA' and char_length(public_key::text) < 1000),
  created_at   timestamptz not null default now()
);

-- Passkey + encrypted key backup columns (added to existing tables too).
alter table public.profiles add column if not exists credential_id         text;
alter table public.profiles add column if not exists credential_public_key text;
alter table public.profiles add column if not exists credential_alg        integer;
alter table public.profiles add column if not exists key_backup            jsonb;
create unique index if not exists profiles_credential_id_key on public.profiles(credential_id) where credential_id is not null;
alter table public.profiles drop constraint if exists profiles_passkey_check;
alter table public.profiles add constraint profiles_passkey_check check (
  credential_alg is null or credential_alg in (-7, -257)) not valid;
alter table public.profiles drop constraint if exists profiles_backup_size;
alter table public.profiles add constraint profiles_backup_size check (
  key_backup is null or char_length(key_backup::text) < 8000) not valid;

create table if not exists public.messages (
  id                uuid primary key default gen_random_uuid(),
  sender            text not null references public.profiles(username),
  recipient         text not null references public.profiles(username),
  iv                text not null check (char_length(iv) <= 64),
  ciphertext        text not null check (char_length(ciphertext) <= 30000),
  key_for_recipient text not null check (char_length(key_for_recipient) <= 1000),
  key_for_sender    text not null check (char_length(key_for_sender) <= 1000),
  created_at        timestamptz not null default now()
);

create index if not exists messages_recipient_idx on public.messages (recipient, created_at desc);
create index if not exists messages_sender_idx    on public.messages (sender, created_at desc);

alter table public.profiles enable row level security;
alter table public.messages enable row level security;

-- Read + insert only. No update/delete policies, so nobody can edit or remove
-- anyone's profile, passkey or messages through the public API.
drop policy if exists "profiles_read"   on public.profiles;
drop policy if exists "profiles_insert" on public.profiles;
drop policy if exists "messages_read"   on public.messages;
drop policy if exists "messages_insert" on public.messages;

create policy "profiles_read"   on public.profiles for select to anon, authenticated using (true);
-- New accounts must carry a passkey and an encrypted key backup.
create policy "profiles_insert" on public.profiles for insert to anon, authenticated
  with check (credential_id is not null and credential_public_key is not null
              and credential_alg in (-7, -257) and key_backup is not null);
create policy "messages_read"   on public.messages for select to anon, authenticated using (true);
create policy "messages_insert" on public.messages for insert to anon, authenticated with check (true);

revoke all on public.profiles, public.messages from anon, authenticated;
grant select, insert on public.profiles, public.messages to anon, authenticated;
