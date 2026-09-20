import { z } from 'zod';
import { originSchema, mechanismSchema } from './observation.js';
import { overrideClassSchema, reasonCodeSchema, ruleEffectSchema } from './policy.js';
import { riskCategorySchema, riskFactorSchema, riskUncertaintySchema } from './risk.js';
import { signalSchema } from './domain-intel.js';

export const decisionOutcomeSchema = z.enum(['ALLOW', 'WARN', 'BLOCK', 'ASK_USER']);
export type DecisionOutcome = z.infer<typeof decisionOutcomeSchema>;

// The pattern lives in policy.ts so rules and decisions cannot drift apart.
export { reasonCodeSchema };

/**
 * The explanation shown to the user and stored for audit.
 *
 * PRD.md section 9 fixes its content: website, requested data, why, matched
 * rules. No vault plaintext appears here.
 */
export const decisionExplanationSchema = z.strictObject({
  website: z.string().min(1).max(255),
  origin: originSchema,
  requested_data: z.array(z.string().min(1).max(128)).max(64),
  why: z.array(z.string().min(1).max(300)).min(1).max(16),
  domain_signals: z.array(signalSchema).max(32),
  matched_rules: z.array(z.string().min(1).max(32)).max(200),
  policy_version: z.string().min(1).max(32),
  overridden: z.boolean(),
});
export type DecisionExplanation = z.infer<typeof decisionExplanationSchema>;

/**
 * A conflict between rules at equal priority.
 *
 * Recorded in the decision rather than resolved silently, so a policy author can
 * see that two rules disagree and why the more restrictive one won.
 */
export const decisionConflictSchema = z.strictObject({
  kind: z.enum(['equal_priority_opposing_effects', 'user_rule_neutralised_by_critical']),
  rule_ids: z.array(z.string().min(1).max(32)).min(2).max(64),
  effects: z.array(ruleEffectSchema).min(2).max(4),
  resolved_effect: ruleEffectSchema,
  detail: z.string().min(1).max(300),
});
export type DecisionConflict = z.infer<typeof decisionConflictSchema>;

/** A rule that stayed silent, and why. Silence is reported, never assumed. */
export const unevaluatedRuleSchema = z.strictObject({
  rule_id: z.string().min(1).max(32),
  reason: z.enum(['signal_missing', 'signal_stale', 'out_of_scope', 'expired']),
  detail: z.string().min(1).max(300),
});
export type UnevaluatedRuleRecord = z.infer<typeof unevaluatedRuleSchema>;

export const decisionSchema = z.strictObject({
  decision_id: z.uuid(),
  request_id: z.uuid(),
  decision: decisionOutcomeSchema,
  risk_score: z.number().min(0).max(100),
  risk_level: riskCategorySchema,
  risk_factors: z.array(riskFactorSchema).max(24),
  reason_codes: z.array(reasonCodeSchema).max(32),
  matched_rules: z.array(z.string().min(1).max(32)).max(200),
  /** The data categories this decision judged, so the audit trail can name them (W6.4). */
  classified_categories: z.array(z.string().min(1).max(36)).max(64).optional(),
  override_class: overrideClassSchema,
  /** Derived from override_class; a critical block is never overridable. */
  overridable: z.boolean(),
  policy_version: z.string().min(1).max(32),
  /** How much of the score rested on inputs that were unavailable or stale. */
  uncertainty: riskUncertaintySchema,
  conflicts: z.array(decisionConflictSchema).max(16),
  unevaluated_rules: z.array(unevaluatedRuleSchema).max(200),
  explanation: decisionExplanationSchema,
  /** True when a critical security block is the reason for refusal. */
  critical_security_block: z.boolean(),
  created_at: z.iso.datetime(),
});
export type Decision = z.infer<typeof decisionSchema>;

/** Force Allow is a separate, explicit, audited action. */
export const overrideRequestSchema = z.strictObject({
  decision_id: z.uuid(),
  reason: z.string().min(3).max(300),
});
export type OverrideRequest = z.infer<typeof overrideRequestSchema>;

export const overrideResultSchema = z.strictObject({
  audit_id: z.uuid(),
  authorization_grant: z
    .strictObject({
      grant: z.string().min(1).max(4096),
      expires_at: z.iso.datetime(),
      /** The exact fields this grant may release - never a broader scope. */
      approved_fields: z.array(z.string().min(1).max(128)).min(1).max(64),
      data_category_id: z.string().min(1).max(36),
    })
    .nullable(),
  /** True when the decision was critical and no override was issued. */
  refused: z.boolean(),
  refusal_reason: z.string().max(200).nullable(),
});
export type OverrideResult = z.infer<typeof overrideResultSchema>;

/**
 * Enforcement attestation (`W7.5`, `T031`).
 *
 * The extension returns this for a block it was asked to enforce. Only an
 * attested block may be recorded as enforced; an unattested block is stored
 * as unenforced so the audit cannot overstate protection (`D-025`).
 */
export const enforcementAttestationSchema = z.strictObject({
  enforced: z.boolean(),
  mechanism: mechanismSchema,
  at: z.iso.datetime(),
  /** The decision's blocking rule id, when a specific rule produced it. */
  rule_id: z.string().min(1).max(32).nullable(),
  /** Why enforcement was not possible, when enforced is false. "platform" means the browser cannot prevent it. */
  not_enforced_reason: z.string().max(200).nullable(),
});
export type EnforcementAttestation = z.infer<typeof enforcementAttestationSchema>;

/**
 * Force Allow request body (W6.5).
 *
 * The field set is deliberately fixed: an unspecified key in a strict object is
 * refused, so a crafted body cannot smuggle a scope, a decision id of its own
 * choosing or a critical-block bypass into the flow.
 */
export const forceAllowRequestSchema = z.strictObject({
  decision_id: z.uuid(),
  reason: z.string().min(3).max(300),
});
export type ForceAllowRequest = z.infer<typeof forceAllowRequestSchema>;

/**
 * A stored authorization grant (Phase 7).
 *
 * The token itself is returned once, at issue time; what is stored is its
 * identifier and scope, so a database read cannot yield a usable grant.
 */
export const authorizationGrantSchema = z.strictObject({
  jti: z.uuid(),
  request_id: z.uuid(),
  user_id: z.uuid(),
  decision_id: z.uuid(),
  /** The vault entry this grant may release; null for a local-tier release. */
  data_id: z.uuid().nullable(),
  data_category_id: z.string().min(1).max(36),
  /** The exact fields this grant may release - never a wider set. */
  approved_fields: z.array(z.string().min(1).max(128)).min(1).max(64),
  recipient: z.string().min(1).max(253),
  policy_version: z.string().min(1).max(32),
  issued_at: z.iso.datetime(),
  expires_at: z.iso.datetime(),
  consumed_at: z.iso.datetime().nullable(),
  revoked_at: z.iso.datetime().nullable(),
});
export type AuthorizationGrant = z.infer<typeof authorizationGrantSchema>;

/** Owner-facing record of grants issued for a decision. */
export const grantListSchema = z.strictObject({
  decision_id: z.uuid(),
  grants: z.array(
    z.strictObject({
      jti: z.uuid(),
      data_id: z.uuid().nullable(),
      data_category_id: z.string().min(1).max(36),
      approved_fields: z.array(z.string().min(1).max(128)).min(1).max(64),
      recipient: z.string().min(1).max(253),
      policy_version: z.string().min(1).max(32),
      issued_at: z.iso.datetime(),
      expires_at: z.iso.datetime(),
      consumed_at: z.iso.datetime().nullable(),
      revoked_at: z.iso.datetime().nullable(),
    }),
  ),
});
export type GrantList = z.infer<typeof grantListSchema>;

/**
 * Policy versions recorded with every decision (W5.6).
 *
 * Two components: the versioned ruleset as data, and the user policy epoch,\n * which advances on every user-rule mutation. Both are combined into the single
 * `policy_version` string recorded in decisions and audits.
 */
export const policyVersionSchema = z.strictObject({
  ruleset_version: z.string().min(1).max(32),
  user_policy_epoch: z.number().int().min(1),
  /** `ruleset_version@epoch` - the reproducibility handle stored on decisions. */
  policy_version: z.string().min(1).max(64),
});
export type PolicyVersion = z.infer<typeof policyVersionSchema>;

export function formatPolicyVersion(rulesetVersion: string, userPolicyEpoch: number): string {
  return `${rulesetVersion}@${userPolicyEpoch}`;
}
export function parsePolicyVersion(value: string): PolicyVersion | null {
  const match = /^([A-Za-z0-9.-]{1,32})@(\d{1,10})$/.exec(value);
  if (!match) return null;
  return { ruleset_version: match[1]!, user_policy_epoch: Number(match[2]), policy_version: value };
}

export const disclosureRequestSchema = z.strictObject({
  grant: z.string().min(16).max(4096),
  /** What the caller now wants released; a superset of the grant is refused. */
  fields: z.array(z.string().min(1).max(128)).min(1).max(64),
  recipient: z.string().min(1).max(253),
  /**
   * Local-tier values already fetched through the owner's extension gesture.
   * Present only for local-tier releases; the gateway never accepts these from
   * anyone but the authenticated owner.
   */
  local_values: z.record(z.string().min(1).max(128), z.string().max(4096)).optional(),
});
export type DisclosureRequest = z.infer<typeof disclosureRequestSchema>;

export const disclosureResultSchema = z.strictObject({
  disclosure_id: z.uuid(),
  released_fields: z.array(z.string().min(1).max(128)).max(64),
  data_category_id: z.string().min(1).max(36),
  recipient: z.string().min(1).max(253),
  /** Present for server-tier entries; a local-tier release happens client-side. */
  values: z.record(z.string(), z.string()).nullable(),
  storage_tier: z.enum(['local', 'server']),
  disclosed_at: z.iso.datetime(),
});
export type DisclosureResult = z.infer<typeof disclosureResultSchema>;

export const disclosureFailureSchema = z.strictObject({
  refused: z.literal(true),
  reason: z.enum([
    'grant_unknown',
    'grant_malformed',
    'grant_expired',
    'grant_consumed',
    'grant_revoked',
    'scope_expanded',
    'recipient_mismatch',
    'policy_changed',
    'not_authorized',
    'consent_missing',
    'consent_revoked',
    'entry_missing',
    'local_data_unavailable',
  ]),
  detail: z.string().min(1).max(300),
});
export type DisclosureFailure = z.infer<typeof disclosureFailureSchema>;
