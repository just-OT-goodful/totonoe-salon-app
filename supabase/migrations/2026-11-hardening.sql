-- 公開前の安全対策（schema.sql の後に実行。冪等）
-- ・管理者ログインを「パスコード → 12時間有効のトークン」方式に変更し、連続失敗でロック
-- ・予約作成時の入力検証（電話番号・日付・営業時間・件数上限）と同時予約の排他制御
-- ・キャンセル期限を日本時間の前日24:00に統一
-- ・自分の予約履歴の取得に「電話番号＋氏名」を必須化
-- ・オーナー宛メールの重複送信防止フラグ

alter table public.app_settings
  add column if not exists failed_attempts int not null default 0,
  add column if not exists locked_until timestamptz,
  add column if not exists pin_changed boolean not null default false;

alter table public.bookings
  add column if not exists owner_notified boolean not null default false;

create table if not exists public.admin_sessions (
  token_hash text primary key,
  expires_at timestamptz not null
);
alter table public.admin_sessions enable row level security;

-- 以降の管理者用関数は p_pin 引数にトークンを受け取る（引数名は互換のため据え置き）
create or replace function public._check_pin(p_pin text) returns boolean
language sql security definer set search_path = public, extensions as $$
  select exists(
    select 1 from public.admin_sessions
    where token_hash = encode(digest(coalesce(p_pin, ''), 'sha256'), 'hex') and expires_at > now()
  );
$$;

create or replace function public.admin_login(p_pin text) returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
declare s record; v_token text;
begin
  select * into s from public.app_settings where id = 1;
  if s.locked_until is not null and s.locked_until > now() then
    return jsonb_build_object('ok', false, 'locked', true);
  end if;
  if s.pin_hash = crypt(coalesce(p_pin, ''), s.pin_hash) then
    update public.app_settings set failed_attempts = 0, locked_until = null where id = 1;
    delete from public.admin_sessions where expires_at < now();
    v_token := encode(gen_random_bytes(24), 'hex');
    insert into public.admin_sessions(token_hash, expires_at)
    values (encode(digest(v_token, 'sha256'), 'hex'), now() + interval '12 hours');
    return jsonb_build_object('ok', true, 'token', v_token, 'default_pin', not s.pin_changed);
  end if;
  if s.failed_attempts + 1 >= 5 then
    update public.app_settings set failed_attempts = 0, locked_until = now() + interval '15 minutes' where id = 1;
    return jsonb_build_object('ok', false, 'locked', true);
  end if;
  update public.app_settings set failed_attempts = failed_attempts + 1 where id = 1;
  return jsonb_build_object('ok', false, 'locked', false);
end;
$$;
grant execute on function public.admin_login to anon, authenticated;

drop function if exists public.admin_change_pin(text, text);
create or replace function public.admin_change_pin(p_token text, p_old_pin text, p_new_pin text)
returns boolean
language plpgsql security definer set search_path = public, extensions as $$
begin
  if not public._check_pin(p_token) then raise exception 'invalid_pin'; end if;
  if not exists (select 1 from public.app_settings where id = 1 and pin_hash = crypt(coalesce(p_old_pin, ''), pin_hash)) then
    raise exception 'invalid_old_pin';
  end if;
  if p_new_pin is null or length(p_new_pin) < 6 then raise exception 'pin_too_short'; end if;
  update public.app_settings set pin_hash = crypt(p_new_pin, gen_salt('bf')), pin_changed = true where id = 1;
  return true;
end;
$$;
grant execute on function public.admin_change_pin to anon, authenticated;

drop function if exists public.my_bookings(text);
create or replace function public.my_bookings(p_phone text, p_name text)
returns setof public.bookings
language sql security definer set search_path = public, extensions as $$
  select * from public.bookings
  where regexp_replace(normalize(phone, NFKC), '[^0-9]', '', 'g') = regexp_replace(normalize(coalesce(p_phone, ''), NFKC), '[^0-9]', '', 'g')
    and regexp_replace(normalize(coalesce(p_phone, ''), NFKC), '[^0-9]', '', 'g') <> ''
    and regexp_replace(normalize(name, NFKC), '\s', '', 'g') = regexp_replace(normalize(coalesce(p_name, ''), NFKC), '\s', '', 'g')
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
  v_digits text;
  v_phone text;
  v_pending int;
  v_row public.bookings;
begin
  v_phone := normalize(trim(coalesce(p_phone, '')), NFKC);
  v_digits := regexp_replace(v_phone, '[^0-9]', '', 'g');
  if length(v_digits) not between 10 and 11 then raise exception 'invalid_phone'; end if;
  if length(trim(coalesce(p_name, ''))) = 0 or length(p_name) > 50 then raise exception 'invalid_name'; end if;
  if coalesce(p_email, '') <> '' and (length(p_email) > 100 or p_email !~ '^[^@\s]+@[^@\s]+\.[^@\s]+$') then
    raise exception 'invalid_email';
  end if;
  if p_date_key !~ '^\d{4}-\d{2}-\d{2}$' or p_start !~ '^\d{2}:\d{2}$' or p_end !~ '^\d{2}:\d{2}$' then
    raise exception 'invalid_date';
  end if;
  if p_date_key::date < (now() at time zone 'Asia/Tokyo')::date then raise exception 'past_date'; end if;
  if p_start < '13:00' or p_end > '17:00' or p_start >= p_end then raise exception 'outside_hours'; end if;

  perform pg_advisory_xact_lock(hashtext(p_date_key));

  select count(*) into v_pending from public.bookings
  where status = 'pending' and regexp_replace(normalize(phone, NFKC), '[^0-9]', '', 'g') = v_digits;
  if v_pending >= 3 then raise exception 'too_many_pending'; end if;

  select * into v_settings from public.app_settings where id = 1;
  if v_settings.closed_dates @> to_jsonb(p_date_key) then raise exception 'closed_date'; end if;

  select exists(
    select 1 from jsonb_array_elements(v_settings.blocked_slots) b
    where b->>'dateKey' = p_date_key and b->>'time' = p_start
  ) into v_blocked;
  if v_blocked then raise exception 'blocked_slot'; end if;

  select exists(
    select 1 from public.bookings b
    where b.date_key = p_date_key and b.status in ('pending','confirmed')
      and p_start < b.end_time and p_end > b.start_time
  ) into v_overlap;
  if v_overlap then raise exception 'slot_taken'; end if;

  insert into public.bookings(id, date_key, start_time, end_time, name, phone, email, menu_name, price, status)
  values (p_id, p_date_key, p_start, p_end, trim(p_name), v_phone, coalesce(p_email, ''), p_menu_name, p_price, 'pending')
  returning * into v_row;
  return v_row;
end;
$$;
grant execute on function public.create_booking to anon, authenticated;

create or replace function public.cancel_booking(p_id text, p_phone text)
returns boolean
language plpgsql security definer set search_path = public, extensions as $$
declare v_row public.bookings; v_in text;
begin
  v_in := regexp_replace(normalize(coalesce(p_phone, ''), NFKC), '[^0-9]', '', 'g');
  select * into v_row from public.bookings where id = p_id;
  if not found then raise exception 'not_found'; end if;
  if v_in = '' or regexp_replace(normalize(v_row.phone, NFKC), '[^0-9]', '', 'g') <> v_in then
    raise exception 'phone_mismatch';
  end if;
  if v_row.status = 'cancelled' then return true; end if;
  if now() >= ((v_row.date_key::date)::timestamp at time zone 'Asia/Tokyo') then
    raise exception 'deadline_passed';
  end if;
  update public.bookings set status = 'cancelled' where id = p_id;
  return true;
end;
$$;
grant execute on function public.cancel_booking to anon, authenticated;
