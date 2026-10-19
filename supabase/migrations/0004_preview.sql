-- PakkaOrder 0004: anon preview by unguessable token (rate-limited by event cap)
create or replace function public.confirm_preview(p_token text)
returns jsonb language plpgsql security definer set search_path = public as $$
declare v public.orders;
begin
  select * into v from public.orders where confirm_token = p_token;
  if not found then raise exception 'Link not valid' using errcode = '40401'; end if;
  insert into public.confirm_events (order_id, event) values (v.id, 'preview');
  return jsonb_build_object(
    'order_ref', v.order_ref,
    'name', v.customer_name,
    'address', v.customer_address,
    'city', coalesce(v.customer_city, ''),
    'pincode', coalesce(v.customer_pincode, ''),
    'cod', v.cod_amount,
    'status', v.status);
end $$;
revoke all on function public.confirm_preview(text) from public;
grant execute on function public.confirm_preview(text) to anon, authenticated;
