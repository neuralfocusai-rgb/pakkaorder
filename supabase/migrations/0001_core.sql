-- PakkaOrder core schema (independent project)
create extension if not exists pgcrypto;

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  role text not null default 'brand' check (role in ('brand','admin')),
  brand_id uuid,
  created_at timestamptz not null default now()
);

create table if not exists public.brands (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  whatsapp text not null,
  email text,
  city text,
  plan text not null default 'free',
  credits integer not null default 20,
  active boolean not null default false,
  created_at timestamptz not null default now()
);

create table if not exists public.orders (
  id uuid primary key default gen_random_uuid(),
  brand_id uuid not null references public.brands(id) on delete cascade,
  order_ref text not null,
  customer_name text not null,
  customer_phone text not null,
  customer_address text not null,
  customer_city text,
  customer_pincode text,
  cod_amount numeric(10,2),
  status text not null default 'pending'
    check (status in ('pending','link_sent','confirmed','risky','fake','expired')),
  confirm_token text unique,
  risk_score integer not null default 0,
  confirmed_at timestamptz,
  created_at timestamptz not null default now()
);

create table if not exists public.confirm_events (
  id uuid primary key default gen_random_uuid(),
  order_id uuid not null references public.orders(id) on delete cascade,
  event text not null,
  lang text,
  meta jsonb default '{}',
  created_at timestamptz not null default now()
);

create table if not exists public.credit_ledger (
  id uuid primary key default gen_random_uuid(),
  brand_id uuid not null references public.brands(id) on delete cascade,
  delta integer not null,
  reason text not null,
  receipt_ref text,
  created_at timestamptz not null default now()
);

create index if not exists idx_orders_brand on public.orders(brand_id, created_at desc);
create index if not exists idx_orders_token on public.orders(confirm_token);
create index if not exists idx_events_order on public.confirm_events(order_id);
