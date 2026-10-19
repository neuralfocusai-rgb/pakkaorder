-- PakkaOrder 0003: secure write paths (SECURITY DEFINER RPCs only)

create or replace function public.register_brand(
  p_name text, p_whatsapp text, p_email text default null, p_city text default null)
returns public.brands language plpgsql security definer set search_path = public as $$
declare v_brand public.brands;
begin
  if auth.uid() is null then raise exception 'Must be signed in' using errcode = '42501'; end if;
  insert into public.brands (name, whatsapp, email, city, active, credits)
  values (p_name, p_whatsapp, p_email, p_city, false, 20) returning * into v_brand;
  update public.profiles set brand_id = v_brand.id
  where id = auth.uid() and brand_id is null;
  return v_brand;
end $$;
revoke all on function public.register_brand(text, text, text, text) from public;
grant execute on function public.register_brand(text, text, text, text) to authenticated;

create or replace function public.import_orders(p_orders jsonb)
returns table (id uuid, order_ref text, confirm_token text)
language plpgsql security definer set search_path = public as $$
declare v_brand uuid; v_n int; v_cred int; v_active boolean;
begin
  select brand_id into v_brand from public.profiles where id = auth.uid();
  if v_brand is null then raise exception 'No brand for this user' using errcode = '42501'; end if;
  select credits, active into v_cred, v_active from public.brands where id = v_brand for update;
  if not v_active then raise exception 'Brand not activated yet' using errcode = '42501'; end if;
  v_n := jsonb_array_length(p_orders);
  if v_n = 0 then raise exception 'Empty import'; end if;
  if v_cred < v_n then
    raise exception 'Not enough credits: need %, have %', v_n, v_cred using errcode = '42501';
  end if;
  update public.brands set credits = credits - v_n where id = v_brand;
  insert into public.credit_ledger (brand_id, delta, reason) values (v_brand, -v_n, 'import');
  return query
    insert into public.orders as o (brand_id, order_ref, customer_name, customer_phone,
      customer_address, customer_city, customer_pincode, cod_amount, confirm_token)
    select v_brand, x.order_ref, x.customer_name, x.customer_phone, x.customer_address,
      x.customer_city, x.customer_pincode, x.cod_amount,
      substr(md5(random()::text || clock_timestamp()::text), 1, 12)
    from jsonb_to_recordset(p_orders) as x(
      order_ref text, customer_name text, customer_phone text, customer_address text,
      customer_city text, customer_pincode text, cod_amount numeric(10,2))
    returning o.id, o.order_ref, o.confirm_token;
end $$;
revoke all on function public.import_orders(jsonb) from public;
grant execute on function public.import_orders(jsonb) to authenticated;

create or replace function public.touch_order(p_token text, p_lang text default null)
returns void language plpgsql security definer set search_path = public as $$
declare v_order public.orders;
begin
  select * into v_order from public.orders where confirm_token = p_token for update;
  if not found then raise exception 'Link not valid' using errcode = '40401'; end if;
  insert into public.confirm_events (order_id, event, lang) values (v_order.id, 'opened', p_lang);
  if v_order.status = 'pending' then
    update public.orders set status = 'link_sent' where id = v_order.id;
  end if;
end $$;
revoke all on function public.touch_order(text, text) from public;
grant execute on function public.touch_order(text, text) to anon, authenticated;

create or replace function public.confirm_order(
  p_token text, p_action text, p_address_ok boolean default true,
  p_lang text default null, p_meta jsonb default '{}')
returns public.orders language plpgsql security definer set search_path = public as $$
declare v_order public.orders; v_events int; v_status text;
begin
  select * into v_order from public.orders where confirm_token = p_token for update;
  if not found then raise exception 'Link not valid' using errcode = '40401'; end if;
  if v_order.status in ('confirmed', 'fake', 'expired') then
    raise exception 'Already closed' using errcode = '40901';
  end if;
  select count(*) into v_events from public.confirm_events where order_id = v_order.id;
  if v_events >= 10 then raise exception 'Too many attempts' using errcode = '42901'; end if;
  insert into public.confirm_events (order_id, event, lang, meta)
  values (v_order.id, 'tap_' || p_action, p_lang, p_meta);
  v_status := case
    when p_action = 'yes' and p_address_ok then 'confirmed'
    when p_action = 'yes' then 'risky'
    else 'fake' end;
  update public.orders set
    status = v_status,
    confirmed_at = case when v_status = 'confirmed' then now() else confirmed_at end,
    risk_score = case v_status when 'confirmed' then 0 when 'risky' then 60 else 100 end
  where id = v_order.id returning * into v_order;
  return v_order;
end $$;
revoke all on function public.confirm_order(text, text, boolean, text, jsonb) from public;
grant execute on function public.confirm_order(text, text, boolean, text, jsonb) to anon, authenticated;

create or replace function public.add_credits(
  p_brand_id uuid, p_delta int, p_reason text, p_receipt_ref text default null)
returns public.brands language plpgsql security definer set search_path = public as $$
declare v_brand public.brands;
begin
  if not public.is_admin() then raise exception 'Admin role required' using errcode = '42501'; end if;
  update public.brands set credits = credits + p_delta where id = p_brand_id returning * into v_brand;
  if not found then raise exception 'Brand not found'; end if;
  insert into public.credit_ledger (brand_id, delta, reason, receipt_ref)
  values (p_brand_id, p_delta, p_reason, p_receipt_ref);
  return v_brand;
end $$;
revoke all on function public.add_credits(uuid, int, text, text) from public;
grant execute on function public.add_credits(uuid, int, text, text) to authenticated;
