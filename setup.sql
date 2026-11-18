-- Schichtplan Eisbahn – Datenbank einrichten
-- Komplett in den Supabase SQL Editor einfügen und auf "Run" tippen.

create extension if not exists pgcrypto with schema extensions;

-- ---------- Tabellen ----------
create table if not exists public.sp_config (
  id int primary key default 1 check (id = 1),
  settings jsonb not null
);

create table if not exists public.sp_staff (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  pin_hash text not null,
  phone text default '',
  is_boss boolean not null default false,
  failed int not null default 0,
  locked_until timestamptz,
  created_at timestamptz not null default now()
);
create unique index if not exists sp_staff_name_uq on public.sp_staff (lower(name));

create table if not exists public.sp_sessions (
  token text primary key,
  staff_id uuid not null references public.sp_staff(id) on delete cascade,
  created_at timestamptz not null default now()
);

create table if not exists public.sp_signups (
  shift_key text not null,
  staff_id uuid not null references public.sp_staff(id) on delete cascade,
  created_at timestamptz not null default clock_timestamp(),
  primary key (shift_key, staff_id)
);

create table if not exists public.sp_adjust (
  shift_key text not null,
  staff_id uuid not null references public.sp_staff(id) on delete cascade,
  hours numeric not null,
  primary key (shift_key, staff_id)
);

-- Direkter Zugriff von außen ist gesperrt – alles läuft über die Funktionen unten.
alter table public.sp_config   enable row level security;
alter table public.sp_staff    enable row level security;
alter table public.sp_sessions enable row level security;
alter table public.sp_signups  enable row level security;
alter table public.sp_adjust   enable row level security;
revoke all on public.sp_config, public.sp_staff, public.sp_sessions, public.sp_signups, public.sp_adjust from anon, authenticated;

-- ---------- Startwerte (Öffnungszeiten laut Flyer 2026/27) ----------
insert into public.sp_config (id, settings) values (1, '{
  "seasonStart": "2026-11-27",
  "seasonEnd": "2027-02-28",
  "seats": 2,
  "seatsWeek": {"0":3,"1":2,"2":2,"3":2,"4":2,"5":2,"6":3},
  "pre": 0, "post": 0,
  "week": {"0":"10:30-12:30, 14:00-16:30","1":"","2":"15:00-17:30","3":"15:00-17:30, 19:00-21:30","4":"15:00-17:30","5":"15:00-17:30","6":"10:30-12:30, 14:00-16:30"},
  "special": "23.12.2026 + 10:30-12:30\n24.12.2026 10:30-12:30\n25.12.2026 10:30-12:30, 14:00-16:30 (3)\n26.12.2026 10:30-12:30, 14:00-16:30 (3)\n29.12.2026 + 10:30-12:30\n30.12.2026 + 10:30-12:30\n31.12.2026 10:30-12:30\n01.01.2027 10:30-12:30, 14:00-16:30 (3)\n05.01.2027 + 10:30-12:30\n06.01.2027 + 10:30-12:30\n07.01.2027 + 10:30-12:30\n08.01.2027 + 10:30-12:30\n02.02.2027 + 10:30-12:30",
  "wages": [{"from":"2026-01-01","rate":13.90},{"from":"2027-01-01","rate":14.60}],
  "minijob": [{"from":"2026-01-01","limit":603},{"from":"2027-01-01","limit":633}]
}'::jsonb) on conflict (id) do nothing;

-- ---------- Hilfsfunktionen ----------
create or replace function public.sp_me(p_token text) returns public.sp_staff
language plpgsql security definer set search_path = public, extensions as $$
declare s public.sp_staff;
begin
  select st.* into s from sp_sessions se join sp_staff st on st.id = se.staff_id where se.token = p_token;
  if s.id is null then raise exception 'NICHT_ANGEMELDET'; end if;
  return s;
end $$;

create or replace function public.sp_new_token(p_staff uuid) returns text
language plpgsql security definer set search_path = public, extensions as $$
declare t text := encode(extensions.gen_random_bytes(24), 'hex');
begin
  insert into sp_sessions(token, staff_id) values (t, p_staff);
  return t;
end $$;

create or replace function public.sp_shift_start(p_key text) returns timestamptz
language sql immutable set search_path = public as $$
  select (split_part(p_key,'_',1) || ' ' || substr(split_part(p_key,'_',2),1,2) || ':' || substr(split_part(p_key,'_',2),3,2))::timestamp at time zone 'Europe/Berlin'
$$;

-- ---------- Öffentliche Funktionen ----------
create or replace function public.sp_register(p_name text, p_pin text, p_phone text default '') returns json
language plpgsql security definer set search_path = public, extensions as $$
declare v_id uuid; v_boss boolean;
begin
  p_name := btrim(regexp_replace(coalesce(p_name,''), '\s+', ' ', 'g'));
  if length(p_name) < 2 or length(p_name) > 40 then raise exception 'NAME_UNGUELTIG'; end if;
  if p_pin !~ '^\d{4,8}$' then raise exception 'PIN_UNGUELTIG'; end if;
  if exists (select 1 from sp_staff where lower(name) = lower(p_name)) then raise exception 'NAME_VERGEBEN'; end if;
  v_boss := not exists (select 1 from sp_staff);   -- erstes Konto = Chef-Konto
  insert into sp_staff(name, pin_hash, phone, is_boss)
    values (p_name, extensions.crypt(p_pin, extensions.gen_salt('bf')), left(coalesce(p_phone,''),30), v_boss)
    returning id into v_id;
  return json_build_object('token', sp_new_token(v_id));
end $$;

create or replace function public.sp_login(p_name text, p_pin text) returns json
language plpgsql security definer set search_path = public, extensions as $$
declare s sp_staff;
begin
  select * into s from sp_staff where lower(name) = lower(btrim(regexp_replace(coalesce(p_name,''), '\s+', ' ', 'g')));
  if s.id is null then return json_build_object('error', 'FALSCH'); end if;
  if s.locked_until is not null and s.locked_until > now() then return json_build_object('error', 'GESPERRT'); end if;
  if s.pin_hash <> extensions.crypt(coalesce(p_pin,''), s.pin_hash) then
    update sp_staff set
      locked_until = case when failed + 1 >= 5 then now() + interval '15 minutes' else null end,
      failed = case when failed + 1 >= 5 then 0 else failed + 1 end
      where id = s.id;
    return json_build_object('error', 'FALSCH');
  end if;
  update sp_staff set failed = 0, locked_until = null where id = s.id;
  return json_build_object('token', sp_new_token(s.id));
end $$;

create or replace function public.sp_logout(p_token text) returns void
language sql security definer set search_path = public as $$
  delete from sp_sessions where token = p_token;
$$;

create or replace function public.sp_state(p_token text) returns json
language plpgsql security definer set search_path = public, extensions as $$
declare me sp_staff := sp_me(p_token);
begin
  return json_build_object(
    'me', json_build_object('id', me.id, 'name', me.name, 'phone', me.phone, 'is_boss', me.is_boss),
    'settings', (select settings from sp_config where id = 1),
    'staff', coalesce((select json_agg(json_build_object('id', id, 'name', name, 'is_boss', is_boss,
                  'phone', case when me.is_boss then phone else null end) order by name) from sp_staff), '[]'::json),
    'signups', coalesce((select json_agg(json_build_object('k', shift_key, 's', staff_id, 't', (extract(epoch from created_at)*1000)::bigint)) from sp_signups), '[]'::json),
    'adjust', coalesce((select json_agg(json_build_object('k', shift_key, 's', staff_id, 'h', hours)) from sp_adjust), '[]'::json),
    'now', (extract(epoch from now())*1000)::bigint
  );
end $$;

create or replace function public.sp_claim(p_token text, p_key text) returns void
language plpgsql security definer set search_path = public, extensions as $$
declare me sp_staff := sp_me(p_token);
begin
  if p_key !~ '^\d{4}-\d{2}-\d{2}_\d{4}$' then raise exception 'SCHICHT_UNGUELTIG'; end if;
  if sp_shift_start(p_key) <= now() then raise exception 'SCHICHT_BEGONNEN'; end if;
  insert into sp_signups(shift_key, staff_id) values (p_key, me.id) on conflict do nothing;
end $$;

create or replace function public.sp_release(p_token text, p_key text, p_staff uuid default null) returns void
language plpgsql security definer set search_path = public, extensions as $$
declare me sp_staff := sp_me(p_token); target uuid := coalesce(p_staff, me.id);
begin
  if target <> me.id and not me.is_boss then raise exception 'NICHT_ERLAUBT'; end if;
  if target = me.id and not me.is_boss and sp_shift_start(p_key) <= now() then raise exception 'SCHICHT_BEGONNEN'; end if;
  delete from sp_signups where shift_key = p_key and staff_id = target;
  delete from sp_adjust where shift_key = p_key and staff_id = target;
end $$;

create or replace function public.sp_update_profile(p_token text, p_name text, p_phone text) returns void
language plpgsql security definer set search_path = public, extensions as $$
declare me sp_staff := sp_me(p_token);
begin
  p_name := btrim(regexp_replace(coalesce(p_name,''), '\s+', ' ', 'g'));
  if length(p_name) < 2 or length(p_name) > 40 then raise exception 'NAME_UNGUELTIG'; end if;
  if exists (select 1 from sp_staff where lower(name) = lower(p_name) and id <> me.id) then raise exception 'NAME_VERGEBEN'; end if;
  update sp_staff set name = p_name, phone = left(coalesce(p_phone,''),30) where id = me.id;
end $$;

create or replace function public.sp_change_pin(p_token text, p_old text, p_new text) returns void
language plpgsql security definer set search_path = public, extensions as $$
declare me sp_staff := sp_me(p_token);
begin
  if me.pin_hash <> extensions.crypt(coalesce(p_old,''), me.pin_hash) then raise exception 'FALSCH'; end if;
  if p_new !~ '^\d{4,8}$' then raise exception 'PIN_UNGUELTIG'; end if;
  update sp_staff set pin_hash = extensions.crypt(p_new, extensions.gen_salt('bf')) where id = me.id;
end $$;

-- ---------- Nur Chef ----------
create or replace function public.sp_save_settings(p_token text, p_settings jsonb) returns void
language plpgsql security definer set search_path = public, extensions as $$
declare me sp_staff := sp_me(p_token);
begin
  if not me.is_boss then raise exception 'NICHT_ERLAUBT'; end if;
  update sp_config set settings = p_settings where id = 1;
end $$;

create or replace function public.sp_set_adjust(p_token text, p_key text, p_staff uuid, p_hours numeric) returns void
language plpgsql security definer set search_path = public, extensions as $$
declare me sp_staff := sp_me(p_token);
begin
  if not me.is_boss then raise exception 'NICHT_ERLAUBT'; end if;
  if p_hours is null then
    delete from sp_adjust where shift_key = p_key and staff_id = p_staff;
  else
    if p_hours < 0 or p_hours > 24 then raise exception 'STUNDEN_UNGUELTIG'; end if;
    insert into sp_adjust(shift_key, staff_id, hours) values (p_key, p_staff, p_hours)
      on conflict (shift_key, staff_id) do update set hours = excluded.hours;
  end if;
end $$;

create or replace function public.sp_reset_pin(p_token text, p_staff uuid, p_new text) returns void
language plpgsql security definer set search_path = public, extensions as $$
declare me sp_staff := sp_me(p_token);
begin
  if not me.is_boss then raise exception 'NICHT_ERLAUBT'; end if;
  if p_new !~ '^\d{4,8}$' then raise exception 'PIN_UNGUELTIG'; end if;
  update sp_staff set pin_hash = extensions.crypt(p_new, extensions.gen_salt('bf')), failed = 0, locked_until = null where id = p_staff;
  delete from sp_sessions where staff_id = p_staff;
end $$;

create or replace function public.sp_delete_staff(p_token text, p_staff uuid) returns void
language plpgsql security definer set search_path = public, extensions as $$
declare me sp_staff := sp_me(p_token);
begin
  if not me.is_boss then raise exception 'NICHT_ERLAUBT'; end if;
  if p_staff = me.id then raise exception 'NICHT_ERLAUBT'; end if;
  delete from sp_staff where id = p_staff;
end $$;

-- ---------- Rechte: nur die Funktionen sind von außen aufrufbar ----------
revoke all on function public.sp_me(text), public.sp_new_token(uuid), public.sp_shift_start(text) from public, anon, authenticated;
grant execute on function
  public.sp_register(text,text,text), public.sp_login(text,text), public.sp_logout(text),
  public.sp_state(text), public.sp_claim(text,text), public.sp_release(text,text,uuid),
  public.sp_update_profile(text,text,text), public.sp_change_pin(text,text,text),
  public.sp_save_settings(text,jsonb), public.sp_set_adjust(text,text,uuid,numeric),
  public.sp_reset_pin(text,uuid,text), public.sp_delete_staff(text,uuid)
to anon, authenticated;
