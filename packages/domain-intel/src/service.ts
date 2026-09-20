import {
  summarizeSignals,
  unknownSignal,
  type DomainSignal,
  type IntelligenceSummary,
  type SignalType,
} from '@pv/schemas';
import { cacheKey, deriveCacheState, noCache, SingleFlight, type IntelligenceCache } from './cache.js';
import { isNonPublicHost, markFreshnessIfStale, registrableDomain, computeFreshness, type DomainIntelligenceProvider, type FreshnessWindow } from './provider.js';
import {
  attempt,
  CircuitBreaker,
  DEFAULT_POLICY,
  RateLimiter,
  type AttemptDependencies,
  type FailureReason,
  type ResiliencePolicy,
} from './resilience.js';

export interface FailureRecord {
  provider_id: string;
  signal_type: SignalType;
  reason: FailureReason;
  attempts: number;
  detail: string;
}

export interface CollectOptions {
  host: string;
  providers: readonly DomainIntelligenceProvider[];
  cache?: IntelligenceCache;
  window: FreshnessWindow;
  policy?: Partial<ResiliencePolicy>;
  now?: Date;
  dependencies?: AttemptDependencies;
  singleFlight?: SingleFlight;
  /**
   * Per-provider runtime state (rate limiter, circuit breaker, single-flight).
   * Supplied by the caller so the budgets persist across requests instead of
   * resetting on every call; created per call when omitted.
   */
  state?: ProviderRuntimeState;
}

export interface ProviderRuntimeState {
  limiters: Map<string, RateLimiter>;
  breakers: Map<string, CircuitBreaker>;
  singleFlight: SingleFlight;
}

export function createProviderRuntime(): ProviderRuntimeState {
  return { limiters: new Map(), breakers: new Map(), singleFlight: new SingleFlight() };
}

export interface CollectResult {
  summary: IntelligenceSummary;
  failures: FailureRecord[];
  /** True when at least one upstream call was made during this request. */
  upstream_called: boolean;
}

/** Negative caching window: short, so a transient outage is retried soon. */
export const UNKNOWN_CACHE_TTL_SECONDS = 60;

function providerSignalType(provider: DomainIntelligenceProvider): SignalType {
  return provider.produces[0] ?? 'reputation';
}

/**
 * Collect domain intelligence for one host (`T014`--`T018`).
 *
 * Guarantees relied on by the decision layer:
 *  - every failure becomes an explicit `unknown` signal with a reason;
 *  - nothing here can produce a permissive value;
 *  - a cache miss is resolved upstream, never treated as trust;
 *  - non-public hosts are never sent to external providers.
 */
export async function collectIntelligence(options: CollectOptions): Promise<CollectResult> {
  const now = options.now ?? new Date();
  const cache = options.cache ?? noCache;
  const singleFlight = options.singleFlight ?? new SingleFlight();
  const policy: ResiliencePolicy = { ...DEFAULT_POLICY, ...options.policy };
  const state: ProviderRuntimeState = options.state ?? createProviderRuntime();
  const host = options.host.toLowerCase().replace(/\.$/, '');
  const signals: DomainSignal[] = [];
  const failures: FailureRecord[] = [];
  let hits = 0;
  let upstreamCalled = false;

  if (isNonPublicHost(host)) {
    for (const provider of options.providers) {
      signals.push(
        unknownSignal(
          providerSignalType(provider),
          provider.provider_id,
          'non-public host: no external provider is contacted',
          now.toISOString(),
        ),
      );
    }
    return {
      summary: summarizeSignals(host, signals, 'disabled'),
      failures,
      upstream_called: false,
    };
  }

  for (const provider of options.providers) {
    const signalType = providerSignalType(provider);
    const key = cacheKey(host, signalType);
    const cached = await cache.get(key);

    if (cached !== null) {
      const freshness = computeFreshness(cached.stored_at, now, options.window);
      if (freshness !== 'expired') {
        hits += 1;
        signals.push(
          freshness === 'stale' && cached.signal.freshness !== 'unknown'
            ? markFreshnessIfStale(cached.signal, 'stale')
            : cached.signal,
        );
        continue;
      }
      await cache.delete(key);
    }

    const limiter = state.limiters.get(provider.provider_id) ?? new RateLimiter(policy.rateLimitPerMinute);
    state.limiters.set(provider.provider_id, limiter);
    const breaker =
      state.breakers.get(provider.provider_id) ??
      new CircuitBreaker(policy.circuitFailureThreshold, policy.circuitCooldownMs);
    state.breakers.set(provider.provider_id, breaker);

    const outcome = await singleFlight.run(key, async () => {
      if (cached === null) {
        upstreamCalled = true;
      }
      return attempt((signal) => provider.lookup({ host, registrable_domain: registrableDomain(host), now, signal }), {
        policy,
        limiter,
        breaker,
        ...(options.dependencies === undefined ? {} : { dependencies: options.dependencies }),
      });
    });

    const result = outcome.value;
    if (result.ok) {
      signals.push(result.value);
      await cache.set(key, {
        signal: result.value,
        stored_at: now.toISOString(),
        ttl_seconds:
          result.value.freshness === 'unknown' ? UNKNOWN_CACHE_TTL_SECONDS : options.window.ttlSeconds,
      });
    } else {
      failures.push({
        provider_id: provider.provider_id,
        signal_type: signalType,
        reason: result.reason,
        attempts: result.attempts,
        detail: result.detail,
      });
      const fallback = unknownSignal(
        signalType,
        provider.provider_id,
        `${result.reason}: ${result.detail}`,
        now.toISOString(),
      );
      signals.push(fallback);
      await cache.set(key, {
        signal: fallback,
        stored_at: now.toISOString(),
        ttl_seconds: UNKNOWN_CACHE_TTL_SECONDS,
      });
    }
  }

  return {
    summary: summarizeSignals(host, signals, deriveCacheState(hits, signals.length, cache)),
    failures,
    upstream_called: upstreamCalled,
  };
}

/**
 * Degradation ladder, documented as data so the policy is reviewable:
 * freshest signal -> stale signal marked stale -> unknown signal -> continue with
 * a privacy-first posture. There is deliberately no "assume benign" rung.
 */
export const DEGRADATION_LADDER = [
  'fresh signal',
  'stale signal, marked stale with its original retrieval time',
  'unknown signal with a reason',
  'continue enforcement with heightened uncertainty (never a permissive default)',
] as const;
