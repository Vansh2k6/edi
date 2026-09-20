import { z } from 'zod';
import { mechanismSchema } from './observation.js';
import { sensitivitySchema } from './vault.js';
import { signalTypeSchema } from './domain-intel.js';

/** Consent state. `Pending` exists because a request is scored before granting. */
export const consentStatusSchema = z.enum(['Pending', 'Active', 'Revoked', 'Expired']);
export type ConsentStatus = z.infer<typeof consentStatusSchema>;

export const permissionTypeSchema = z.enum(['Read', 'Write', 'Analyze', 'Share']);
export type PermissionType = z.infer<typeof permissionTypeSchema>;

export const consentSchema = z.strictObject({
  consent_id: z.uuid(),
  user_id: z.uuid(),
  application_id: z.string().min(1).max(36),
  data_category_id: z.string().min(1).max(36),
  permission_type: permissionTypeSchema,
  expiry_date: z.iso.date().nullable(),
  consent_status: consentStatusSchema,
});
export type Consent = z.infer<typeof consentSchema>;

export const ruleEffectSchema = z.enum(['allow', 'warn', 'block', 'ask_user']);
export type RuleEffect = z.infer<typeof ruleEffectSchema>;

/**
 * `overridable` blocks may be Force-Allowed by the owner; `critical` blocks may
 * not, and only the system may author them (D-029).
 */
export const overrideClassSchema = z.enum(['overridable', 'critical']);
export type OverrideClass = z.infer<typeof overrideClassSchema>;

export const ruleScopeSchema = z.strictObject({
  data_categories: z.array(z.string().min(1).max(36)).max(120).default([]),
  origins: z.array(z.string().min(1).max(253)).max(200).default([]),
  applications: z.array(z.string().min(1).max(36)).max(200).default([]),
});

/**
 * Rule conditions are a typed expression tree rather than an evaluated string,
 * so a condition can be inspected, validated and tested without an interpreter
 * sandbox (W5.1).
 */
export type RuleCondition =
  | { op: 'and'; operands: RuleCondition[] }
  | { op: 'or'; operands: RuleCondition[] }
  | { op: 'not'; operand: RuleCondition }
  | { op: 'category_in'; categories: string[] }
  | { op: 'mechanism_in'; mechanisms: z.infer<typeof mechanismSchema>[] }
  | { op: 'sensitivity_at_least'; level: z.infer<typeof sensitivitySchema> }
  | { op: 'signal_is'; signal: z.infer<typeof signalTypeSchema>; value: string | number | boolean }
  | { op: 'signal_unknown'; signal: z.infer<typeof signalTypeSchema> }
  | { op: 'domain_age_days_lt'; days: number };

export const ruleConditionSchema: z.ZodType<RuleCondition> = z.lazy(() =>
  z.union([
    z.strictObject({ op: z.literal('and'), operands: z.array(ruleConditionSchema).min(1).max(16) }),
    z.strictObject({ op: z.literal('or'), operands: z.array(ruleConditionSchema).min(1).max(16) }),
    z.strictObject({ op: z.literal('not'), operand: ruleConditionSchema }),
    z.strictObject({ op: z.literal('category_in'), categories: z.array(z.string().min(1).max(36)).min(1).max(120) }),
    z.strictObject({ op: z.literal('mechanism_in'), mechanisms: z.array(mechanismSchema).min(1).max(6) }),
    z.strictObject({ op: z.literal('sensitivity_at_least'), level: sensitivitySchema }),
    z.strictObject({
      op: z.literal('signal_is'),
      signal: signalTypeSchema,
      value: z.union([z.string().max(512), z.number(), z.boolean()]),
    }),
    z.strictObject({ op: z.literal('signal_unknown'), signal: signalTypeSchema }),
    z.strictObject({ op: z.literal('domain_age_days_lt'), days: z.number().int().min(0).max(36500) }),
  ]),
);

export const ruleIdSchema = z.string().regex(/^R-[A-Z0-9-]{2,32}$/, 'rule ids look like R-DOMAIN-02');
export const reasonCodePattern = /^[A-Z0-9_]{3,48}$/;
export const reasonCodeSchema = z.string().regex(reasonCodePattern);

export const ruleSchema = z.strictObject({
  rule_id: ruleIdSchema,
  ruleset_version: z.string().min(1).max(32),
  condition: ruleConditionSchema,
  effect: ruleEffectSchema,
  priority: z.number().int().min(0).max(10000),
  scope: ruleScopeSchema,
  rationale: z.string().min(1).max(500),
  override_class: overrideClassSchema,
  /** `system` rules are not editable by users; `user` rules are. */
  origin: z.enum(['system', 'user']),
  /** Machine-readable code recorded on every decision this rule affects. */
  reason_code: reasonCodeSchema,
  expires_at: z.iso.datetime().nullable().default(null),
});
export type Rule = z.infer<typeof ruleSchema>;

/**
 * The posture a ruleset documents for requests no rule matched.
 *
 * It is data rather than an implicit fallthrough, so "what happens by default"
 * is reviewable in the same file as the rules themselves (W5.3).
 */
export const defaultPostureSchema = z.strictObject({
  effect: ruleEffectSchema,
  override_class: overrideClassSchema,
  rationale: z.string().min(1).max(500),
  reason_code: reasonCodeSchema,
});
export type DefaultPosture = z.infer<typeof defaultPostureSchema>;

export const rulesetSchema = z.strictObject({
  ruleset_version: z.string().min(1).max(32),
  /** sha256 of the canonicalised rules, verified at load (W5.3). */
  checksum: z.string().regex(/^[0-9a-f]{64}$/),
  default_posture: defaultPostureSchema,
  rules: z.array(ruleSchema).min(1).max(500),
});
export type Ruleset = z.infer<typeof rulesetSchema>;

/**
 * A user-authored rule.
 *
 * `origin` and `ruleset_version` are assigned by the system, and
 * `override_class` is absent by construction: a user rule cannot express the
 * critical class at all, so privilege escalation is not a validation special
 * case that could be forgotten (D-029).
 */
export const userRuleInputSchema = z.strictObject({
  rule_id: ruleIdSchema.optional(),
  condition: ruleConditionSchema,
  effect: ruleEffectSchema,
  priority: z.number().int().min(0).max(8999),
  scope: ruleScopeSchema,
  rationale: z.string().min(3).max(500),
  expires_at: z.iso.datetime().nullable().default(null),
});
export type UserRuleInput = z.infer<typeof userRuleInputSchema>;

/**
 * Stored form of a user rule, as returned by the rules API.
 *
 * System-assigned fields are present and asserted: a response that omitted
 * `override_class` could not be told apart from one that forged it.
 */
export const userRuleRecordSchema = z.strictObject({
  rule: ruleSchema,
  created_at: z.iso.datetime(),
  updated_at: z.iso.datetime(),
});
export type UserRuleRecord = z.infer<typeof userRuleRecordSchema>;

/**
 * What a proposed user rule would shadow, shown before saving (`T022`).
 *
 * A new/edited rule also carries the policy_version it would join, so the client
 * can see the version bump it is about to cause.
 */
export const ruleConflictPreviewSchema = z.strictObject({
  shadows: z.array(
    z.strictObject({
      rule_id: ruleIdSchema,
      origin: z.enum(['system', 'user']),
      effect: ruleEffectSchema,
      priority: z.number().int(),
      detail: z.string().min(1).max(300),
    }),
  ),
  /** Rules the proposal cannot beat, e.g. a system rule at equal priority. */
  neutralised_by: z.array(ruleIdSchema),
  /** Set when the proposal itself would be refused. */
  rejected_reason: z.string().min(1).max(300).nullable(),
  policy_version: z.string().min(1).max(32),
});
export type RuleConflictPreview = z.infer<typeof ruleConflictPreviewSchema>;
