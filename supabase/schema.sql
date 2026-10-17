-- 整えサロン予約アプリ: Supabase スキーマ
-- 冪等（何度実行してもOK）。RLSは有効化のみでテーブルへの直接ポリシーは作らず、
-- すべて SECURITY DEFINER の関数（RPC）経由でアクセスする。

create extension if not exists pgcrypto;

-- ============================================================
-- テーブル
-- ============================================================

create table if not exists public.bookings (
  id text primary key,
  date_key text not null,
  start_time text not null,
  end_time text not null,
  name text not null,
  phone text not null,
  email text not null default '',
  menu_name text not null,
  price integer not null,
  status text not null default 'pending' check (status in ('pending','confirmed','cancelled')),
  created_at timestamptz not null default now()
);
alter table public.bookings enable row level security;

create table if not exists public.app_settings (
  id int primary key default 1,
  announcement text not null default '',
  contact_info jsonb not null default '{}'::jsonb,
  closed_dates jsonb not null default '[]'::jsonb,
  blocked_slots jsonb not null default '[]'::jsonb,
  menu_items jsonb not null default '[]'::jsonb,
  pin_hash text not null,
  updated_at timestamptz not null default now(),
  constraint single_row check (id = 1)
);
alter table public.app_settings enable row level security;

insert into public.app_settings (id, pin_hash)
values (1, crypt('0000', gen_salt('bf')))
on conflict (id) do nothing;

-- ============================================================
-- 内部ヘルパー（パスコード照合）
-- ============================================================

create or replace function public._check_pin(p_pin text) returns boolean
language sql security definer set search_path = public, extensions as $$
  select exists(
    select 1 from public.app_settings where id = 1 and pin_hash = crypt(coalesce(p_pin, ''), pin_hash)
  );
$$;

-- ============================================================
-- お客様向け（認証不要・anon実行可）
-- ============================================================

create or replace function public.get_public_settings()
returns table(announcement text, contact_info jsonb, closed_dates jsonb, blocked_slots jsonb, menu_items jsonb)
language sql security definer set search_path = public, extensions as $$
  select announcement, contact_info, closed_dates, blocked_slots, menu_items
  from public.app_settings where id = 1;
$$;
grant execute on function public.get_public_settings to anon, authenticated;

-- 空き状況の判定用。個人情報（氏名・電話・メール）は含めない。
create or replace function public.list_bookings_public()
returns table(date_key text, start_time text, end_time text, status text)
language sql security definer set search_path = public, extensions as $$
  select date_key, start_time, end_time, status from public.bookings
  where status in ('pending','confirmed');
$$;
grant execute on function public.list_bookings_public to anon, authenticated;

-- 電話番号の数字だけを比較して、自分の予約履歴を取得する（ログイン機能はないため）。
create or replace function public.my_bookings(p_phone text)
returns setof public.bookings
language sql security definer set search_path = public, extensions as $$
  select * from public.bookings
  where regexp_replace(phone, '[^0-9]', '', 'g') = regexp_replace(coalesce(p_phone, ''), '[^0-9]', '', 'g')
    and regexp_replace(coalesce(p_phone, ''), '[^0-9]', '', 'g') <> ''
  order by date_key, start_time;
$$;
grant execute on function public.my_bookings to anon, authenticated;

create or replace function public.create_booking(
  p_id text, p_date_key text, p_start text, p_end text,
  p_name text, p_phone text, p_email text, p_menu_name text, p_price integer
) returns public.bookings
language plpgsql security definer set search_path = public, extensions as $$
declare
  v_settings record;
  v_blocked boolean;
  v_overlap boolean;
  v_row public.bookings;
begin
  select * into v_settings from public.app_settings where id = 1;

  if v_settings.closed_dates @> to_jsonb(p_date_key) then
    raise exception 'closed_date';
  end if;

  select exists(
    select 1 from jsonb_array_elements(v_settings.blocked_slots) b
    where b->>'dateKey' = p_date_key and b->>'time' = p_start
  ) into v_blocked;
  if v_blocked then
    raise exception 'blocked_slot';
  end if;

  select exists(
    select 1 from public.bookings b
    where b.date_key = p_date_key
      and b.status in ('pending','confirmed')
      and p_start < b.end_time and p_end > b.start_time
  ) into v_overlap;
  if v_overlap then
    raise exception 'slot_taken';
  end if;

  insert into public.bookings(id, date_key, start_time, end_time, name, phone, email, menu_name, price, status)
  values (p_id, p_date_key, p_start, p_end, p_name, p_phone, coalesce(p_email, ''), p_menu_name, p_price, 'pending')
  returning * into v_row;

  return v_row;
end;
$$;
grant execute on function public.create_booking to anon, authenticated;

-- お客様自身によるキャンセル。電話番号が一致し、前日24:00を過ぎていない場合のみ許可。
create or replace function public.cancel_booking(p_id text, p_phone text)
returns boolean
language plpgsql security definer set search_path = public, extensions as $$
declare v_row public.bookings;
begin
  select * into v_row from public.bookings where id = p_id;
  if not found then raise exception 'not_found'; end if;
  if regexp_replace(v_row.phone, '[^0-9]', '', 'g') <> regexp_replace(coalesce(p_phone, ''), '[^0-9]', '', 'g') then
    raise exception 'phone_mismatch';
  end if;
  if v_row.status = 'cancelled' then
    return true;
  end if;
  if now() >= (v_row.date_key::date)::timestamptz then
    raise exception 'deadline_passed';
  end if;
  update public.bookings set status = 'cancelled' where id = p_id;
  return true;
end;
$$;
grant execute on function public.cancel_booking to anon, authenticated;

-- ============================================================
-- 管理者向け（パスコードをDB側で照合。RLSにより直接のテーブルアクセスは不可）
-- ============================================================

create or replace function public.admin_verify_pin(p_pin text) returns boolean
language sql security definer set search_path = public, extensions as $$
  select public._check_pin(p_pin);
$$;
grant execute on function public.admin_verify_pin to anon, authenticated;

create or replace function public.admin_list_bookings(p_pin text)
returns setof public.bookings
language plpgsql security definer set search_path = public, extensions as $$
begin
  if not public._check_pin(p_pin) then raise exception 'invalid_pin'; end if;
  return query select * from public.bookings order by date_key, start_time;
end;
$$;
grant execute on function public.admin_list_bookings to anon, authenticated;

create or replace function public.admin_set_booking_status(p_pin text, p_id text, p_status text)
returns public.bookings
language plpgsql security definer set search_path = public, extensions as $$
declare v_row public.bookings;
begin
  if not public._check_pin(p_pin) then raise exception 'invalid_pin'; end if;
  if p_status not in ('pending','confirmed','cancelled') then raise exception 'invalid_status'; end if;
  update public.bookings set status = p_status where id = p_id returning * into v_row;
  if not found then raise exception 'not_found'; end if;
  return v_row;
end;
$$;
grant execute on function public.admin_set_booking_status to anon, authenticated;

create or replace function public.admin_update_settings(
  p_pin text, p_announcement text, p_contact_info jsonb,
  p_closed_dates jsonb, p_blocked_slots jsonb, p_menu_items jsonb
) returns void
language plpgsql security definer set search_path = public, extensions as $$
begin
  if not public._check_pin(p_pin) then raise exception 'invalid_pin'; end if;
  update public.app_settings set
    announcement = coalesce(p_announcement, announcement),
    contact_info = coalesce(p_contact_info, contact_info),
    closed_dates = coalesce(p_closed_dates, closed_dates),
    blocked_slots = coalesce(p_blocked_slots, blocked_slots),
    menu_items = coalesce(p_menu_items, menu_items),
    updated_at = now()
  where id = 1;
end;
$$;
grant execute on function public.admin_update_settings to anon, authenticated;

create or replace function public.admin_change_pin(p_old_pin text, p_new_pin text)
returns boolean
language plpgsql security definer set search_path = public, extensions as $$
begin
  if not public._check_pin(p_old_pin) then raise exception 'invalid_pin'; end if;
  if p_new_pin is null or length(p_new_pin) < 4 then raise exception 'pin_too_short'; end if;
  update public.app_settings set pin_hash = crypt(p_new_pin, gen_salt('bf')) where id = 1;
  return true;
end;
$$;
grant execute on function public.admin_change_pin to anon, authenticated;
