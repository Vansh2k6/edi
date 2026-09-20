import { signalSchema, type DomainSignal, type SignalType } from '@pv/schemas';

// Host classification and registrable-domain logic live in @pv/schemas so the
// extension and the core cannot drift apart. Re-exported here for callers that
// only depend on this package.
export { isNonPublicHost, registrableDomain } from '@pv/schemas';

/**
 * Provider abstraction (`T014`).
 *
 * A provider either returns a schema-valid signal or throws. It may not return
 * an unlabeled value, an empty string, or a silently defaulted field: converting
 * a failure into an explicit `unknown` signal is the orchestrator's job, so that
 * every provider gets the same treatment and no failure can look like data.
 */
export interface ProviderContext {
  host: string;
  registrable_domain: string | null;
  now: Date;
  signal: AbortSignal;
}

export interface DomainIntelligenceProvider {
  readonly provider_id: string;
  /** Signal types this provider can produce. */
  readonly produces: readonly SignalType[];
  lookup(context: ProviderContext): Promise<DomainSignal>;
}

export interface FreshnessWindow {
  /** Beyond this age a signal is served but marked stale. */
  staleAfterSeconds: number;
  /** Beyond this age the cached value is discarded entirely. */
  ttlSeconds: number;
}

export function computeFreshness(
  retrievedAtIso: string,
  now: Date,
  window: FreshnessWindow,
): 'fresh' | 'stale' | 'expired' {
  const retrieved = Date.parse(retrievedAtIso);
  if (Number.isNaN(retrieved)) return 'expired';
  const ageSeconds = (now.getTime() - retrieved) / 1000;
  if (ageSeconds < 0) return 'expired';
  if (ageSeconds >= window.ttlSeconds) return 'expired';
  if (ageSeconds >= window.staleAfterSeconds) return 'stale';
  return 'fresh';
}

export function markFreshnessIfStale(signal: DomainSignal, freshness: 'fresh' | 'stale'): DomainSignal {
  return signalSchema.parse({ ...signal, freshness });
}

/** Provider-agnostic, non-identifying source label. */
export function sourceLabel(providerId: string, detail?: string): string {
  return detail ? `${providerId}:${detail}` : providerId;
}
