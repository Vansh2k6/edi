import { z } from 'zod';

/**
 * Audit request and response contracts for the core routes (W9.2, T039).
 *
 * These live beside the audit event schema: a viewer response is part of the
 * boundary too, and one that must never become a way to read deleted history or
 * another owner's rows.
 */

/** Newest-first, cursor-paginated list of one owner's audit events. */
export const auditViewerResponseSchema = z.strictObject({
  events: z.array(z.strictObject({
    audit_id: z.uuid(),
    timestamp: z.iso.datetime(),
    actor: z.string().min(1).max(24),
    actor_ref: z.string().max(150).nullable(),
    origin_domain: z.string().max(253).nullable(),
    requested_categories: z.array(z.string().min(1).max(36)).max(64),
    risk_level: z.string().max(12).nullable(),
    decision: z.string().max(12).nullable(),
    override: z.boolean(),
    matched_rules: z.array(z.string().min(1).max(32)).max(200),
    entry_hash: z.string().regex(/^[0-9a-f]{64}$/),
  })),
  next_cursor: z.string().max(80).nullable(),
});

export type AuditViewerResponse = z.infer<typeof auditViewerResponseSchema>;

/**
 * Verification report (W9.2).
 *
 * `chain_intact` false always names the first broken link, its record and its
 * timestamp, so an operator learns where the history stops being trustworthy
 * rather than just that it did.
 */
export const auditVerificationReportSchema = z.strictObject({
  chain_intact: z.boolean(),
  actor_chains: z.array(
    z.strictObject({
      actor: z.string().min(1).max(24),
      actor_ref: z.string().max(150).nullable(),
      records: z.number().int().min(0),
      intact: z.boolean(),
    }),
  ),
  first_broken: z
    .strictObject({
      audit_id: z.uuid(),
      actor: z.string().min(1).max(24),
      actor_ref: z.string().max(150).nullable(),
      timestamp: z.iso.datetime(),
      detail: z.string().min(1).max(300),
    })
    .nullable(),
  verified_at: z.iso.datetime(),
});
export type AuditVerificationReport = z.infer<typeof auditVerificationReportSchema>;

/**
 * A retention tombstone as surfaced through the audit viewer.
 *
 * It records that deletion happened, how much, and over what range - never any
 * content, because a tombstone that carried field names or identifiers would
 * defeat its own purpose (D-019).
 */
export const retentionTombstoneSchema = z.strictObject({
  tombstone_id: z.uuid(),
  record_type: z.string().min(1).max(64),
  deleted_count: z.number().int().min(0),
  deleted_before: z.iso.datetime(),
  run_at: z.iso.datetime(),
  batches: z.number().int().min(1),
});
export type RetentionTombstone = z.infer<typeof retentionTombstoneSchema>;
