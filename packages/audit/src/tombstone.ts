import { z } from 'zod';

/**
 * Retention tombstone (W9.3, D-019).
 *
 * It records that deletion happened, how much, and over what time range -
 * never any content: no identifiers, no field names, no categories. A tombstone
 * that carried row ids would defeat the erasure it exists to record.
 */
export const retentionTombstoneSchema = z.strictObject({
  tombstone_id: z.uuid(),
  record_type: z.string().min(1).max(64),
  deleted_count: z.number().int().min(0),
  /** Exclusive upper bound: records strictly older than this were removed. */
  deleted_before: z.iso.datetime(),
  run_at: z.iso.datetime(),
  batches: z.number().int().min(1),
  /** The policy window in days that authorised the deletion. */
  window_days: z.number().int().min(1),
});
export type RetentionTombstone = z.infer<typeof retentionTombstoneSchema>;

/** The record types retention is allowed to touch, with their config keys. */
export const RETENTION_RECORD_TYPES = ['audit', 'decision', 'tombstone'] as const;
export type RetentionRecordType = (typeof RETENTION_RECORD_TYPES)[number];

/**
 * Validate one retention window from configuration.
 *
 * Zero, negative and non-integer values are refused here rather than at
 * deletion time: a worker that ran with a window of "0 days = delete
 * everything" would be one config typo away from erasing the audit trail.
 */
export function parseRetentionWindowDays(value: number, recordType: string): number {
  if (!Number.isInteger(value) || value <= 0) {
    throw new Error(`retention window for ${recordType} must be a positive integer of days`);
  }
  return value;
}

/** The inclusive/exclusive rule, documented once and tested. */
export function retentionCutoff(now: Date, windowDays: number): Date {
  return new Date(now.getTime() - windowDays * 24 * 60 * 60 * 1000);
}

/**
 * Is a record eligible for deletion?
 *
 * The boundary is exclusive: a record exactly at the cutoff stays one more
 * cycle. "Older than" is `timestamp < cutoff`, never `<=`, so a record written
 * exactly `windowDays` ago is not deleted by a worker whose clock is a
 * millisecond ahead of the writer's.
 */
export function isExpired(timestamp: string, cutoff: Date): boolean {
  return Date.parse(timestamp) < cutoff.getTime();
}
