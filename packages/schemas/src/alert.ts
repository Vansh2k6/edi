import { z } from 'zod';
import { riskCategorySchema } from './risk.js';

export const alertStatusSchema = z.enum(['Open', 'Acknowledged', 'Resolved']);
export type AlertStatus = z.infer<typeof alertStatusSchema>;

export const alertTypeSchema = z.enum([
  'critical_block',
  'override_granted',
  'repeated_blocked_attempts',
  'high_risk_consent_request',
  'provider_failure_storm',
  'audit_chain_broken',
  'retention_job_failed',
]);
export type AlertType = z.infer<typeof alertTypeSchema>;

export const securityAlertSchema = z.strictObject({
  alert_id: z.uuid(),
  alert_type: alertTypeSchema,
  severity: riskCategorySchema,
  /** Never contains vault plaintext or personal data. */
  description: z.string().min(1).max(500),
  status: alertStatusSchema,
  /** Stable identity of the underlying situation, used to deduplicate repeats. */
  fingerprint: z.string().min(8).max(128),
  occurrence_count: z.number().int().min(1),
  first_seen: z.iso.datetime(),
  last_seen: z.iso.datetime(),
  related_decision_id: z.uuid().nullable(),
  related_audit_id: z.uuid().nullable(),
  acknowledged_by: z.string().max(150).nullable(),
  acknowledged_at: z.iso.datetime().nullable(),
  resolved_by: z.string().max(150).nullable(),
  resolved_at: z.iso.datetime().nullable(),
  resolution_reason: z.string().max(300).nullable(),
});
export type SecurityAlert = z.infer<typeof securityAlertSchema>;

export const alertTransitionRequestSchema = z.strictObject({
  alert_id: z.uuid(),
  status: z.enum(['Acknowledged', 'Resolved']),
  reason: z.string().min(3).max(300).nullable().default(null),
});
export type AlertTransitionRequest = z.infer<typeof alertTransitionRequestSchema>;
