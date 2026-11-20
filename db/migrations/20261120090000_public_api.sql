-- The public API (/api/v1) for other systems, such as an internal operating
-- system that sends its own PDFs for signature, and the webhooks that tell
-- that system what happened to them. The tables are separate from the
-- envelopes they point at, so the app works the same with no API in use.

-- An API key acts for the administrator who made it. Only a SHA-256 hash
-- of the key is kept: the key itself is shown once, when it is made.
create table if not exists public.api_keys (
  id text primary key,
  name text not null,
  user_id text not null references public."user"(id) on delete cascade,
  key_hash text not null unique,
  -- The start of the key, shown in Settings so a key can be recognised.
  key_prefix text not null,
  created_at bigint not null,
  last_used_at bigint,
  revoked_at bigint
);

create index if not exists api_keys_user_idx on public.api_keys (user_id);

-- Envelopes made through the API: which key made them (a key sees only
-- these), the caller's own reference, and the caller's names for the
-- signers. webhook_cursor is the last audit event turned into webhooks.
create table if not exists public.api_envelopes (
  envelope_id text primary key references public.envelopes(id) on delete cascade,
  api_key_id text not null references public.api_keys(id) on delete cascade,
  external_id text,
  signer_keys jsonb not null default '{}'::jsonb,
  webhook_cursor integer not null default 0,
  created_at bigint not null
);

create index if not exists api_envelopes_key_idx on public.api_envelopes (api_key_id);
create index if not exists api_envelopes_external_idx
  on public.api_envelopes (api_key_id, external_id);

-- One row per Idempotency-Key, so a repeated request returns the envelope
-- the first one made and never sends twice. Kept for 30 days.
create table if not exists public.api_idempotency_keys (
  api_key_id text not null references public.api_keys(id) on delete cascade,
  idempotency_key text not null,
  request_hash text not null,
  envelope_id text references public.envelopes(id) on delete set null,
  created_at bigint not null,
  primary key (api_key_id, idempotency_key)
);

create index if not exists api_idempotency_keys_created_idx
  on public.api_idempotency_keys (created_at);

-- Where webhooks go. One endpoint per install. The signing secret is kept
-- encrypted, because each delivery is signed with it; after a rotation the
-- previous secret is used too, until previous_secret_expires_at.
create table if not exists public.webhook_endpoints (
  id text primary key,
  url text not null,
  secret_ciphertext text not null,
  previous_secret_ciphertext text,
  previous_secret_expires_at bigint,
  created_by text references public."user"(id) on delete set null,
  created_at bigint not null,
  updated_at bigint not null
);

-- Each webhook event and its delivery. One row per audit event, so the
-- same change is never queued twice.
create table if not exists public.webhook_deliveries (
  id text primary key,
  envelope_id text not null references public.envelopes(id) on delete cascade,
  audit_sequence integer not null,
  event_type text not null,
  occurred_at bigint not null,
  status text not null default 'pending'
    check (status in ('pending', 'delivered', 'failed')),
  attempts integer not null default 0,
  next_attempt_at bigint not null,
  last_attempt_at bigint,
  last_status_code integer,
  last_error text,
  delivered_at bigint,
  created_at bigint not null,
  unique (envelope_id, audit_sequence)
);

create index if not exists webhook_deliveries_due_idx
  on public.webhook_deliveries (status, next_attempt_at);
create index if not exists webhook_deliveries_recent_idx
  on public.webhook_deliveries (created_at desc);
