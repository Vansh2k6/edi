-- Migration 0001 - Phase 1 vault schema (T004, T006).
--
-- Plain SQL so it is reviewable like code. Row-level security is the mechanism
-- that keeps one owner's rows out of another owner's queries, enforced by the
-- database rather than by remembering to add a WHERE clause (T007).
--
-- The session must set `app.user_id` for RLS to admit rows; the core does this
-- through `services/core/src/db/client.ts`.

BEGIN;

CREATE TABLE IF NOT EXISTS users (
  user_id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_name       text NOT NULL,
  email_id        text NOT NULL,
  mobile_number   text,
  identity_status text NOT NULL DEFAULT 'Pending',
  user_type       text NOT NULL DEFAULT 'Citizen',
  created_at      timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS users_email_id_key ON users (email_id);

CREATE TABLE IF NOT EXISTS data_category (
  data_category_id  text PRIMARY KEY,
  category_name     text NOT NULL,
  sensitivity_level text NOT NULL CHECK (sensitivity_level IN ('Low', 'Medium', 'High', 'Critical')),
  active            boolean NOT NULL DEFAULT true
);

CREATE TABLE IF NOT EXISTS application (
  application_id   text PRIMARY KEY,
  application_name text NOT NULL,
  security_rating  integer NOT NULL DEFAULT 0 CHECK (security_rating BETWEEN 0 AND 10),
  active           boolean NOT NULL DEFAULT true
);

CREATE TABLE IF NOT EXISTS encryption_key (
  key_id      uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id     uuid NOT NULL REFERENCES users (user_id) ON DELETE CASCADE,
  algorithm   text NOT NULL DEFAULT 'AES-256-GCM',
  kek_ref     text NOT NULL,
  key_status  text NOT NULL DEFAULT 'Active' CHECK (key_status IN ('Active', 'Rotated', 'Revoked')),
  created_at  timestamptz NOT NULL DEFAULT now(),
  rotated_at  timestamptz
);
CREATE INDEX IF NOT EXISTS encryption_key_user_idx ON encryption_key (user_id, key_status);

CREATE TABLE IF NOT EXISTS vault_entry (
  data_id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id           uuid NOT NULL REFERENCES users (user_id) ON DELETE CASCADE,
  data_category_id  text NOT NULL REFERENCES data_category (data_category_id) ON DELETE RESTRICT,
  encryption_key_id uuid NOT NULL REFERENCES encryption_key (key_id) ON DELETE RESTRICT,
  storage_tier      text NOT NULL CHECK (storage_tier IN ('local', 'server')),
  -- Present only for the server tier. The local tier keeps ciphertext on the client.
  ciphertext        text,
  integrity_digest  text NOT NULL CHECK (integrity_digest ~ '^[0-9a-f]{64}$'),
  -- base64 of the wrapped DEK. Never plaintext key material.
  wrapped_dek       text NOT NULL,
  storage_location  text,
  client_metadata   jsonb NOT NULL DEFAULT '{}'::jsonb,
  data_status       text NOT NULL DEFAULT 'Active' CHECK (data_status IN ('Active', 'Archived', 'Deleted')),
  created_at        timestamptz NOT NULL DEFAULT now(),
  updated_at        timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT vault_entry_tier_ciphertext CHECK (
    (storage_tier = 'server' AND ciphertext IS NOT NULL)
    OR (storage_tier = 'local' AND ciphertext IS NULL)
  )
);
CREATE INDEX IF NOT EXISTS vault_entry_owner_idx ON vault_entry (user_id, data_status);
CREATE INDEX IF NOT EXISTS vault_entry_category_idx ON vault_entry (data_category_id);
CREATE INDEX IF NOT EXISTS vault_entry_key_idx ON vault_entry (encryption_key_id);

CREATE TABLE IF NOT EXISTS consent_policy (
  consent_id       uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id          uuid NOT NULL REFERENCES users (user_id) ON DELETE CASCADE,
  application_id   text NOT NULL REFERENCES application (application_id) ON DELETE CASCADE,
  data_category_id text NOT NULL REFERENCES data_category (data_category_id) ON DELETE RESTRICT,
  permission_type  text NOT NULL CHECK (permission_type IN ('Read', 'Write', 'Analyze', 'Share')),
  expiry_date      text,
  consent_status   text NOT NULL DEFAULT 'Pending'
    CHECK (consent_status IN ('Pending', 'Active', 'Revoked', 'Expired')),
  created_at       timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS consent_owner_idx ON consent_policy (user_id, consent_status);

CREATE TABLE IF NOT EXISTS consent_history (
  history_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  consent_id uuid NOT NULL REFERENCES consent_policy (consent_id) ON DELETE CASCADE,
  action     text NOT NULL,
  changed_by text,
  changed_at timestamptz NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- Row-level security: an owner sees only their own rows.
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION current_owner() RETURNS uuid
LANGUAGE sql STABLE AS $$
  SELECT NULLIF(current_setting('app.user_id', true), '')::uuid
$$;

ALTER TABLE vault_entry ENABLE ROW LEVEL SECURITY;
ALTER TABLE vault_entry FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS vault_entry_owner ON vault_entry;
CREATE POLICY vault_entry_owner ON vault_entry
  USING (user_id = current_owner())
  WITH CHECK (user_id = current_owner());

ALTER TABLE encryption_key ENABLE ROW LEVEL SECURITY;
ALTER TABLE encryption_key FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS encryption_key_owner ON encryption_key;
CREATE POLICY encryption_key_owner ON encryption_key
  USING (user_id = current_owner())
  WITH CHECK (user_id = current_owner());

ALTER TABLE consent_policy ENABLE ROW LEVEL SECURITY;
ALTER TABLE consent_policy FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS consent_policy_owner ON consent_policy;
CREATE POLICY consent_policy_owner ON consent_policy
  USING (user_id = current_owner())
  WITH CHECK (user_id = current_owner());

-- Vault entries are insert-only for status changes made through the API: rows are
-- soft-deleted (data_status = 'Deleted') and the application role cannot remove them.
REVOKE DELETE ON vault_entry FROM PUBLIC;

INSERT INTO data_category (data_category_id, category_name, sensitivity_level) VALUES
  ('CAT-IDENTITY',  'Identity',      'High'),
  ('CAT-CONTACT',   'Communication', 'Low'),
  ('CAT-FINANCIAL', 'Financial',     'Critical'),
  ('CAT-MEDICAL',   'Medical',       'Critical'),
  ('CAT-LOCATION',  'Location',      'Medium'),
  ('CAT-DOCUMENTS', 'Documents',     'High')
ON CONFLICT (data_category_id) DO NOTHING;

COMMIT;
