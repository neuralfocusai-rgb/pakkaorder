-- PakkaOrder 0002: RLS deny-by-default, column locks, helpers
alter table public.profiles enable row level security;
alter table public.brands enable row level security;
alter table public.orders enable row level security;
alter table public.confirm_events enable row level security;
alter table public.credit_ledger enable row level security;

revoke all on public.profiles, public.brands, public.orders,
  public.confirm_events, public.credit_ledger from anon, authenticated;

grant select on public.profiles to authenticated;
grant select on public.brands to authenticated;
grant select on public.orders to authenticated;
grant select on public.credit_ledger to authenticated;
-- confirm_events: zero client access (internal telemetry only)

create or replace function public.handle_new_user() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  insert into public.profiles (id) values (new.id) on conflict do nothing;
  return new;
end $$;
drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created after insert on auth.users
  for each row execute function public.handle_new_user();

create or replace function public.is_admin() returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.profiles where id = auth.uid() and role = 'admin');
$$;
revoke all on function public.is_admin() from public;
grant execute on function public.is_admin() to anon, authenticated;

create or replace function public.owns_brand(p_brand_id uuid) returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.profiles where id = auth.uid() and brand_id = p_brand_id);
$$;
revoke all on function public.owns_brand(uuid) from public;
grant execute on function public.owns_brand(uuid) to authenticated;

create policy profiles_select_own on public.profiles
  for select to authenticated using (id = auth.uid() or public.is_admin());
create policy brands_select_own on public.brands
  for select to authenticated using (public.owns_brand(id) or public.is_admin());
create policy orders_select_own on public.orders
  for select to authenticated using (public.owns_brand(brand_id) or public.is_admin());
create policy ledger_select_own on public.credit_ledger
  for select to authenticated using (public.owns_brand(brand_id) or public.is_admin());
-- no insert/update/delete policies anywhere: writes only via RPCs

create or replace function public.lock_profiles() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  if auth.uid() is not null and not public.is_admin() then
    if new.role is distinct from old.role then
      raise exception 'Role is admin-managed' using errcode = '42501';
    end if;
    if new.brand_id is distinct from old.brand_id and old.brand_id is not null then
      raise exception 'Brand link is immutable' using errcode = '42501';
    end if;
  end if;
  return new;
end $$;
revoke all on function public.lock_profiles() from public;
create trigger trg_lock_profiles before update on public.profiles
  for each row execute function public.lock_profiles();

create or replace function public.lock_brands() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  if auth.uid() is not null and not public.is_admin() then
    if new.credits is distinct from old.credits
       or new.plan is distinct from old.plan
       or new.active is distinct from old.active then
      raise exception 'Only the platform can change credits, plan or active' using errcode = '42501';
    end if;
  end if;
  return new;
end $$;
revoke all on function public.lock_brands() from public;
create trigger trg_lock_brands before update on public.brands
  for each row execute function public.lock_brands();
