-- Migration 0002: decision and privacy_risk_assessment records (W6.6).
--
-- The decision table is the durable record of what the engine decided and
-- why: outcome, risk score and band, reason codes, matched rules, override
-- class and the policy version that produced it. signal_envelope_hashes holds
-- the hashes of the intelligence envelopes in view at decision time, so a
-- later audit can prove which signals were used without duplicating provider
-- data (W6.6).
--
-- Rows are append-only: no UPDATE and no DELETE is granted to anyone, and the
-- application role gets them revoked explicitly. A decision that could be
-- rewritten would not be a record.

CREATE TABLE IF NOT EXISTS decision (
    decision_id              uuid PRIMARY KEY,
    user_id                  uuid NOT NULL REFERENCES users (user_id),
    request_id               uuid NOT NULL,
    decision                 text NOT NULL CHECK (decision IN ('ALLOW', 'WARN', 'BLOCK', 'ASK_USER')),
    risk_score               integer NOT NULL CHECK (risk_score >= 0 AND risk_score <= 100),
    risk_level               text NOT NULL CHECK (risk_level IN ('Low', 'Medium', 'High', 'Critical')),
    reason_codes             text NOT NULL,
    matched_rules            text NOT NULL,
    override_class           text NOT NULL CHECK (override_class IN ('overridable', 'critical')),
    policy_version           text NOT NULL,
    uncertainty              text NOT NULL CHECK (uncertainty IN ('none', 'elevated', 'high')),
    classified_categories    text NOT NULL DEFAULT '[]',
    signal_envelope_hashes   text NOT NULL DEFAULT '[]',
    created_at               timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS decision_owner_idx ON decision (user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS decision_request_idx ON decision (request_id);

ALTER TABLE decision ENABLE ROW LEVEL SECURITY;
ALTER TABLE decision FORCE ROW LEVEL SECURITY;

CREATE POLICY decision_owner ON decision
    USING (user_id = current_setting('app.user_id')::uuid)
    WITH CHECK (user_id = current_setting('app.user_id')::uuid);

-- The risk assessment is stored beside its decision: every factor with its
-- weight, recorded value and whether the input was available, so any score can
-- be reproduced factor by factor (W6.1).
CREATE TABLE IF NOT EXISTS privacy_risk_assessment (
    assessment_id    uuid PRIMARY KEY,
    decision_id      uuid NOT NULL REFERENCES decision (decision_id),
    risk_score       integer NOT NULL CHECK (risk_score >= 0 AND risk_score <= 100),
    risk_level       text NOT NULL CHECK (risk_level IN ('Low', 'Medium', 'High', 'Critical')),
    factor_label     text NOT NULL,
    weight           integer NOT NULL CHECK (weight >= 0 AND weight <= 100),
    factor_value     text,
    detail           text NOT NULL,
    input_unknown    boolean NOT NULL DEFAULT false,
    uncertainty      text NOT NULL CHECK (uncertainty IN ('none', 'elevated', 'high')),
    created_at       timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS risk_assessment_decision_idx ON privacy_risk_assessment (decision_id);

ALTER TABLE privacy_risk_assessment ENABLE ROW LEVEL SECURITY;
ALTER TABLE privacy_risk_assessment FORCE ROW LEVEL SECURITY;

CREATE POLICY privacy_risk_assessment_owner ON privacy_risk_assessment
    USING (
        EXISTS (
            SELECT 1 FROM decision d
            WHERE d.decision_id = privacy_risk_assessment.decision_id
              AND d.user_id = current_setting('app.user_id')::uuid
        )
    )
    WITH CHECK (
        EXISTS (
            SELECT 1 FROM decision d
            WHERE d.decision_id = privacy_risk_assessment.decision_id
              AND d.user_id = current_setting('app.user_id')::uuid
        )
    );

-- W6.5: the override flow writes an audit event containing the actor, the
-- owner's stated reason, the policy version and the overridden decision. The
-- audit table itself was referenced by earlier phases but never migrated, so
-- it is created here with the W6.5 columns included rather than altered in.
-- Chain fields (prev_hash, entry_hash) make an in-place edit detectable; the
-- hash input is the canonical JSON over all columns, so none may be edited.
CREATE TABLE IF NOT EXISTS audit_event (
    audit_id                     uuid PRIMARY KEY,
    request_id                   uuid,
    timestamp                    timestamptz NOT NULL,
    actor                        text NOT NULL CHECK (actor IN ('owner', 'application', 'system', 'retention_job')),
    actor_ref                    text,
    user_id                      uuid REFERENCES users (user_id),
    origin_domain                text,
    requested_categories         text NOT NULL DEFAULT '[]',
    domain_intelligence_summary  text,
    matched_rules                text NOT NULL DEFAULT '[]',
    risk_level                   text CHECK (risk_level IN ('Low', 'Medium', 'High', 'Critical')),
    decision                     text CHECK (decision IN ('ALLOW', 'WARN', 'BLOCK', 'ASK_USER')),
    override                     boolean NOT NULL DEFAULT false,
    override_reason              text,
    classified_categories        text NOT NULL DEFAULT '[]',
    policy_version               text,
    prev_hash                    text,
    entry_hash                   text NOT NULL
);

CREATE INDEX IF NOT EXISTS audit_event_owner_idx ON audit_event (user_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS audit_event_chain_idx ON audit_event (actor, actor_ref, timestamp);

ALTER TABLE audit_event ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_event FORCE ROW LEVEL SECURITY;

CREATE POLICY audit_event_owner ON audit_event
    USING (user_id = current_setting('app.user_id')::uuid)
    WITH CHECK (user_id = current_setting('app.user_id')::uuid);

-- The audit trail is append-only: no role updates or deletes events. Retention
-- (Phase 9) runs as a dedicated role with its own tombstone protocol.
REVOKE UPDATE ON audit_event FROM PUBLIC;
REVOKE DELETE ON audit_event FROM PUBLIC;

-- Decisions are facts, not state: nobody updates or deletes them, including
-- the owner role the application connects as.
REVOKE UPDATE ON decision FROM PUBLIC;
REVOKE DELETE ON decision FROM PUBLIC;
REVOKE UPDATE ON privacy_risk_assessment FROM PUBLIC;
REVOKE DELETE ON privacy_risk_assessment FROM PUBLIC;
