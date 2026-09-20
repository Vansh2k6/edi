-- Migration 0003: enforcement attestation and disclosure refusals (W7.5, T031, W7.2).
--
-- Phase 7 makes the extension's enforcement claim part of the stored record:
-- a decision that was blocked at the network level carries the attestation
-- (mechanism, time, rule, and -- when the platform could not prevent the
-- request -- the honest reason it was not). The audit trail gains the
-- disclosure-refusal channel so a refused disclosure attempt is traceable.
-- Both stay append-only: an enforcement claim that could be edited is not
-- evidence.

-- The decision's enforcement attestation (W7.5). NULL enforced means the
-- decision was never sent to the extension for enforcement; FALSE means an
-- enforcement attempt reported the block as not applied (with a reason).
ALTER TABLE decision
  ADD COLUMN IF NOT EXISTS enforced boolean;
ALTER TABLE decision
  ADD COLUMN IF NOT EXISTS enforcement_mechanism text;
ALTER TABLE decision
  ADD COLUMN IF NOT EXISTS enforced_at timestamptz;
ALTER TABLE decision
  ADD COLUMN IF NOT EXISTS enforcement_rule_id text;
ALTER TABLE decision
  ADD COLUMN IF NOT EXISTS not_enforced_reason text;

-- Attestations arrive after the decision row exists and are never rewritten:
-- UPDATE and DELETE stay revoked from every role (W9.5 carries this further).
REVOKE UPDATE ON decision FROM PUBLIC;
REVOKE DELETE ON decision FROM PUBLIC;

-- The audit trail names disclosure refusals (W7.2) the way it names overrides:
-- a reason channel the chain hash covers, with no plaintext values.
ALTER TABLE audit_event
  ADD COLUMN IF NOT EXISTS refusal_reason text;
ALTER TABLE audit_event
  ADD COLUMN IF NOT EXISTS disclosure_refused boolean DEFAULT FALSE NOT NULL;

REVOKE UPDATE ON audit_event FROM PUBLIC;
REVOKE DELETE ON audit_event FROM PUBLIC;
