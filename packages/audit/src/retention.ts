import {
  isExpired,
  retentionCutoff,
  type RetentionTombstone,
} from './tombstone.js';

/**
 * Retention deletion engine (W9.3, W9.4).
 *
 * The engine is transport-agnostic: the worker in the core supplies a record
 * source and a deleter, and this file owns the policy that both Postgres and
 * in-memory deployments share - bounded batches, retry with backoff, a lock so
 * two workers cannot run concurrently, and a tombstone that records the
 * deletion without recording any content.
 */

export interface RetentionRecord {
  id: string;
  timestamp: string;
}

export interface RetentionStore {
  /** Oldest-first page of candidate records strictly older than `cutoff`. */
  pageExpired(recordType: string, cutoff: Date, batchSize: number): Promise<RetentionRecord[]>;
  /** Delete exactly these ids; returns how many were actually removed. */
  deleteBatch(recordType: string, ids: readonly string[]): Promise<number>;
  /** Record a completed run. */
  writeTombstone(tombstone: RetentionTombstone): Promise<void>;
  /** Advisory lock across workers; true when this caller holds it. */
  acquireLock(): Promise<boolean>;
  releaseLock(): Promise<void>;
  /** The last successful run, for observability (W9.4). */
  lastRun(): Promise<{ run_at: string; deleted: Record<string, number> } | null>;
}

export class RetentionLockError extends Error {
  constructor() {
    super('another retention worker holds the lock');
    this.name = 'RetentionLockError';
  }
}

export interface RetentionRunOptions {
  recordType: string;
  windowDays: number;
  batchSize: number;
  now: Date;
  /** Seconds between retries; a failed batch is retried, never skipped. */
  retryDelaysMs?: readonly number[];
  sleep?: (ms: number) => Promise<void>;
}

export interface RetentionRunResult {
  deleted_count: number;
  batches: number;
  tombstone_id: string;
}

const DEFAULT_RETRY_DELAYS = [100, 200, 400];

/**
 * One retention pass for one record type.
 *
 * Deletion is bounded per batch so a large backlog cannot hold the database in
 * a long transaction, and a batch that fails is retried with backoff - a
 * silent skip would leave records half-retained with nothing to show for it.
 */
export async function runRetentionPass(
  store: RetentionStore,
  options: RetentionRunOptions,
): Promise<RetentionRunResult> {
  if (!Number.isInteger(options.windowDays) || options.windowDays <= 0) {
    throw new Error(`retention window for ${options.recordType} must be a positive integer of days`);
  }
  if (!Number.isInteger(options.batchSize) || options.batchSize <= 0) {
    throw new Error('retention batch size must be a positive integer');
  }
  if (!(await store.acquireLock())) {
    throw new RetentionLockError();
  }

  try {
    const cutoff = retentionCutoff(options.now, options.windowDays);
    const retryDelays = options.retryDelaysMs ?? DEFAULT_RETRY_DELAYS;
    const sleep = options.sleep ?? ((ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms)));

    let deleted = 0;
    let batches = 0;
    let pagesWithMoreWork = true;

    while (pagesWithMoreWork) {
      const expired = await store.pageExpired(options.recordType, cutoff, options.batchSize);
      if (expired.length === 0) break;

      let attempts = 0;
      let removed = 0;
      // Retry the batch until the budget is spent; the error propagates so the
      // caller (and the alert engine) sees the failure rather than a gap.
      for (;;) {
        try {
          removed = await store.deleteBatch(options.recordType, expired.map((record) => record.id));
          break;
        } catch (error) {
          attempts += 1;
          if (attempts > retryDelays.length) throw error;
          await sleep(retryDelays[attempts - 1]!);
        }
      }

      deleted += removed;
      batches += 1;
      pagesWithMoreWork = expired.length === options.batchSize;
    }

    const tombstone: RetentionTombstone = {
      tombstone_id: crypto.randomUUID(),
      record_type: options.recordType,
      deleted_count: deleted,
      deleted_before: cutoff.toISOString(),
      run_at: options.now.toISOString(),
      batches: Math.max(batches, 1),
      window_days: options.windowDays,
    };
    await store.writeTombstone(tombstone);
    await store.recordRun(options.now.toISOString(), { [options.recordType]: deleted });

    return { deleted_count: deleted, batches: Math.max(batches, 1), tombstone_id: tombstone.tombstone_id };
  } finally {
    await store.releaseLock();
  }
}

// Attached to the store interface via declaration merging below.
export interface RetentionStore {
  recordRun(runAt: string, deleted: Record<string, number>): Promise<void>;
}

export { isExpired, retentionCutoff };
