import { z } from 'zod';

/**
 * Domain intelligence contracts (Phase 4, `T014`--`T018`).
 *
 * The invariant this file exists to enforce (D-028): absence of data is never
 * evidence of trust. A signal is either available with a source and a retrieval
 * time, or explicitly unknown with a reason. There is no third state and no
 * default-benign value.
 */

export const signalTypeSchema = z.enum([
  'registration',
  'domain_age',
  'dns',
  'certificate_history',
  'reputation',
  'abuse',
]);
export type SignalType = z.infer<typeof signalTypeSchema>;

export const freshnessSchema = z.enum(['fresh', 'stale', 'unknown']);
export type Freshness = z.infer<typeof freshnessSchema>;

export const signalValueSchema = z.union([z.string().max(512), z.number(), z.boolean(), z.null()]);
export type SignalValue = z.infer<typeof signalValueSchema>;

export const MAX_SOURCE_LENGTH = 128;
export const MAX_UNKNOWN_REASON_LENGTH = 256;

export const signalSchema = z
  .strictObject({
    type: signalTypeSchema,
    value: signalValueSchema,
    /** Provider or subsystem that produced the value. Never a raw user-supplied string. */
    source: z.string().min(1).max(MAX_SOURCE_LENGTH),
    retrieved_at: z.iso.datetime(),
    freshness: freshnessSchema,
    confidence: z.number().min(0).max(1),
    unknown_reason: z.string().min(1).max(MAX_UNKNOWN_REASON_LENGTH).nullable(),
    /** Age of the underlying record in days, when the signal is age-like. */
    age_days: z.number().int().min(-1).max(36500).nullable(),
  })
  .superRefine((signal, ctx) => {
    if (signal.freshness === 'unknown') {
      if (signal.value !== null) {
        ctx.addIssue({
          code: 'custom',
          path: ['value'],
          message: 'an unknown signal must carry a null value, never a benign default',
        });
      }
      if (signal.unknown_reason === null) {
        ctx.addIssue({
          code: 'custom',
          path: ['unknown_reason'],
          message: 'an unknown signal must state why it is unknown',
        });
      }
      if (signal.confidence !== 0) {
        ctx.addIssue({
          code: 'custom',
          path: ['confidence'],
          message: 'an unknown signal has zero confidence',
        });
      }
    } else {
      if (signal.unknown_reason !== null) {
        ctx.addIssue({
          code: 'custom',
          path: ['unknown_reason'],
          message: 'a resolved signal must not carry an unknown reason',
        });
      }
      if (signal.value === null) {
        ctx.addIssue({
          code: 'custom',
          path: ['value'],
          message: 'a resolved signal must carry a value',
        });
      }
    }
  });
export type DomainSignal = z.infer<typeof signalSchema>;

export const intelligenceSummarySchema = z.strictObject({
  host: z.string().min(1).max(253),
  signals: z.array(signalSchema).max(32),
  available_count: z.number().int().min(0),
  unknown_count: z.number().int().min(0),
  stale_count: z.number().int().min(0),
  /** True when nothing at all could be resolved: an explicit uncertainty state. */
  all_unknown: z.boolean(),
  cache_state: z.enum(['hit', 'miss', 'partial', 'disabled']),
});
export type IntelligenceSummary = z.infer<typeof intelligenceSummarySchema>;

export const intelligenceRequestSchema = z.strictObject({
  host: z.string().min(1).max(253),
});

/**
 * Fold a signal list into a summary. Kept here, next to the schema, so the
 * counts cannot drift from the shape they describe.
 */
export function summarizeSignals(
  host: string,
  signals: readonly DomainSignal[],
  cacheState: IntelligenceSummary['cache_state'] = 'disabled',
): IntelligenceSummary {
  let available = 0;
  let unknown = 0;
  let stale = 0;
  for (const signal of signals) {
    if (signal.freshness === 'unknown') unknown += 1;
    else available += 1;
    if (signal.freshness === 'stale') stale += 1;
  }
  return {
    host,
    signals: [...signals],
    available_count: available,
    unknown_count: unknown,
    stale_count: stale,
    all_unknown: signals.length > 0 && available === 0,
    cache_state: cacheState,
  };
}

/** Build an explicit unknown signal. The only sanctioned way to express "no data". */
export function unknownSignal(
  type: SignalType,
  source: string,
  reason: string,
  retrievedAt: string,
): DomainSignal {
  return signalSchema.parse({
    type,
    value: null,
    source,
    retrieved_at: retrievedAt,
    freshness: 'unknown',
    confidence: 0,
    unknown_reason: reason,
    age_days: null,
  });
}
