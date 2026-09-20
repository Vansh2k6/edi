import { z } from 'zod';
import { decisionOutcomeSchema } from './decision.js';
import { riskCategorySchema } from './risk.js';

/**
 * Audit record fields (ARCHITECTURE.md section 5.11).
 *
 * Deliberately absent: vault plaintext, request bodies, full URLs and any
 * personal data beyond what the decision itself requires (D-019).
 */
export const auditActorSchema = z.enum(['owner', 'application', 'system', 'retention_job']);

export const auditEventSchema = z.strictObject({
  audit_id: z.uuid(),
  request_id: z.uuid().nullable(),
  timestamp: z.iso.datetime(),
  actor: auditActorSchema,
  actor_ref: z.string().max(150).nullable(),
  origin_domain: z.string().max(253).nullable(),
  requested_categories: z.array(z.string().min(1).max(36)).max(64),
  domain_intelligence_summary: z.string().max(600).nullable(),
  matched_rules: z.array(z.string().min(1).max(32)).max(200),
  risk_level: riskCategorySchema.nullable(),
  decision: decisionOutcomeSchema.nullable(),
  override: z.boolean(),
  /** The owner's stated reason, recorded when an override was requested (W6.5). */
  override_reason: z.string().min(1).max(300).nullable().optional(),
  /** Why a disclosure was refused; present only on refusal events (W7.2). */
  refusal_reason: z.string().min(1).max(64).optional(),
  /** The consent record the disclosure relied on, when one was used (W7.2). */
  consent_id: z.string().min(1).max(128).optional(),
  /** The data categories the decision judged; set by decision events (W6.4). */
  classified_categories: z.array(z.string().min(1).max(36)).max(64).optional(),
  policy_version: z.string().min(1).max(32).nullable(),
  /** Hash chain: links this record to the previous one for the same actor. */
  prev_hash: z.string().regex(/^[0-9a-f]{64}$/).nullable(),
  entry_hash: z.string().regex(/^[0-9a-f]{64}$/),
});
export type AuditEvent = z.infer<typeof auditEventSchema>;

/** Fields a caller supplies; hashes and ids are derived by the audit service. */
export const auditEventInputSchema = auditEventSchema.omit({
  audit_id: true,
  prev_hash: true,
  entry_hash: true,
});
export type AuditEventInput = z.infer<typeof auditEventInputSchema>;
