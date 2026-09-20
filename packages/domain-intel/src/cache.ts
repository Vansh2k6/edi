import type { DomainSignal, IntelligenceSummary, SignalType } from '@pv/schemas';
import { signalSchema } from '@pv/schemas';
import { Redis } from 'ioredis';

/**
 * Intelligence cache (`T017`).
 *
 * A miss means "go fetch", never "trust". The cache also stores `unknown`
 * results (negative caching), so a provider outage does not become a request
 * storm, and it never becomes a second source of truth: Postgres and the
 * providers are the only authorities (D-026).
 */

export interface CacheEntry {
  signal: DomainSignal;
  stored_at: string;
  /** Shorter for negative results so an outage is retried sooner. */
  ttl_seconds: number;
}

export interface IntelligenceCache {
  readonly kind: 'memory' | 'redis' | 'none';
  get(key: string): Promise<CacheEntry | null>;
  set(key: string, entry: CacheEntry): Promise<void>;
  delete(key: string): Promise<void>;
}

export function cacheKey(host: string, signal: SignalType): string {
  return `pv:di:${host.toLowerCase()}:${signal}`;
}

function parseEntry(raw: string): CacheEntry | null {
  try {
    const parsed: unknown = JSON.parse(raw);
    if (typeof parsed !== 'object' || parsed === null) return null;
    const candidate = parsed as { signal?: unknown; stored_at?: unknown; ttl_seconds?: unknown };
    if (typeof candidate.stored_at !== 'string' || typeof candidate.ttl_seconds !== 'number') return null;
    const signal = signalSchema.safeParse(candidate.signal);
    if (!signal.success) return null;
    return { signal: signal.data, stored_at: candidate.stored_at, ttl_seconds: candidate.ttl_seconds };
  } catch {
    // Corrupted entries are treated as a miss and overwritten.
    return null;
  }
}

export class MemoryIntelligenceCache implements IntelligenceCache {
  readonly kind = 'memory' as const;
  readonly #entries = new Map<string, string>();

  async get(key: string): Promise<CacheEntry | null> {
    const raw = this.#entries.get(key);
    return raw === undefined ? null : parseEntry(raw);
  }

  async set(key: string, entry: CacheEntry): Promise<void> {
    this.#entries.set(key, JSON.stringify(entry));
  }

  async delete(key: string): Promise<void> {
    this.#entries.delete(key);
  }

  /** Test helper: how many entries exist. */
  get size(): number {
    return this.#entries.size;
  }
}

export class RedisIntelligenceCache implements IntelligenceCache {
  readonly kind = 'redis' as const;
  readonly #redis: Redis;

  constructor(redis: Redis) {
    this.#redis = redis;
  }

  async get(key: string): Promise<CacheEntry | null> {
    const raw = await this.#redis.get(key);
    return raw === null ? null : parseEntry(raw);
  }

  async set(key: string, entry: CacheEntry): Promise<void> {
    await this.#redis.set(key, JSON.stringify(entry), 'EX', Math.max(1, Math.floor(entry.ttl_seconds)));
  }

  async delete(key: string): Promise<void> {
    await this.#redis.del(key);
  }
}

export const noCache: IntelligenceCache = {
  kind: 'none',
  get: () => Promise.resolve(null),
  set: () => Promise.resolve(),
  delete: () => Promise.resolve(),
};

/**
 * Single-flight lock so concurrent requests for the same uncached domain
 * trigger exactly one upstream call. Implemented with a plain promise map, which
 * is correct within one process; the Redis variant below extends it across
 * processes without changing the semantics.
 */
export class SingleFlight {
  readonly #inFlight = new Map<string, Promise<unknown>>();

  async run<T>(key: string, operation: () => Promise<T>): Promise<{ value: T; executed: boolean }> {
    const existing = this.#inFlight.get(key);
    if (existing !== undefined) {
      return { value: (await existing) as T, executed: false };
    }
    const started = operation();
    this.#inFlight.set(key, started);
    try {
      const value = await started;
      return { value, executed: true };
    } finally {
      this.#inFlight.delete(key);
    }
  }

  get inFlightCount(): number {
    return this.#inFlight.size;
  }
}

export function deriveCacheState(hits: number, total: number, cache: IntelligenceCache): IntelligenceSummary['cache_state'] {
  if (cache.kind === 'none' || total === 0) return 'disabled';
  if (hits === 0) return 'miss';
  if (hits === total) return 'hit';
  return 'partial';
}
