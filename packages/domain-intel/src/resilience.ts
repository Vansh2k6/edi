/**
 * Provider failure handling (`T018`).
 *
 * Every failure mode ends in a typed reason, never in a value. Nothing in this
 * module can produce a permissive result: the caller turns a failure into an
 * explicit `unknown` signal.
 */

export type FailureReason =
  | 'timeout'
  | 'rate_limited'
  | 'circuit_open'
  | 'auth_failed'
  | 'invalid_response'
  | 'provider_unavailable'
  | 'not_configured';

export interface ResiliencePolicy {
  timeoutMs: number;
  retries: number;
  rateLimitPerMinute: number;
  circuitFailureThreshold: number;
  circuitCooldownMs: number;
}

export const DEFAULT_POLICY: ResiliencePolicy = {
  timeoutMs: 800,
  retries: 2,
  rateLimitPerMinute: 60,
  circuitFailureThreshold: 3,
  circuitCooldownMs: 30_000,
};

export type AttemptResult<T> =
  | { ok: true; value: T }
  | { ok: false; reason: FailureReason; detail: string; attempts: number };

/** Token bucket, refilled continuously. */
export class RateLimiter {
  readonly #capacity: number;
  readonly #refillPerMs: number;
  #tokens: number;
  #lastRefill: number;

  constructor(perMinute: number, now: number = Date.now()) {
    this.#capacity = Math.max(1, perMinute);
    this.#refillPerMs = this.#capacity / 60_000;
    this.#tokens = this.#capacity;
    this.#lastRefill = now;
  }

  tryAcquire(now: number = Date.now()): boolean {
    const elapsed = Math.max(0, now - this.#lastRefill);
    this.#tokens = Math.min(this.#capacity, this.#tokens + elapsed * this.#refillPerMs);
    this.#lastRefill = now;
    if (this.#tokens < 1) return false;
    this.#tokens -= 1;
    return true;
  }
}

type CircuitState = 'closed' | 'open' | 'half_open';

export class CircuitBreaker {
  readonly #threshold: number;
  readonly #cooldownMs: number;
  #failures = 0;
  #openedAt = 0;
  #state: CircuitState = 'closed';

  constructor(threshold: number, cooldownMs: number) {
    this.#threshold = Math.max(1, threshold);
    this.#cooldownMs = cooldownMs;
  }

  get state(): CircuitState {
    return this.#state;
  }

  allows(now: number = Date.now()): boolean {
    if (this.#state === 'open' && now - this.#openedAt >= this.#cooldownMs) {
      this.#state = 'half_open';
    }
    return this.#state !== 'open';
  }

  recordSuccess(): void {
    this.#failures = 0;
    this.#state = 'closed';
  }

  recordFailure(now: number = Date.now()): void {
    if (this.#state === 'half_open') {
      this.#state = 'open';
      this.#openedAt = now;
      return;
    }
    this.#failures += 1;
    if (this.#failures >= this.#threshold) {
      this.#state = 'open';
      this.#openedAt = now;
    }
  }
}

export interface AttemptDependencies {
  fetchImpl?: typeof fetch;
  sleep?: (ms: number) => Promise<void>;
  now?: () => number;
}

const defaultSleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

/** Classify an upstream error into a reason without leaking provider detail. */
export function classifyError(error: unknown): FailureReason {
  if (error instanceof Response) {
    if (error.status === 401 || error.status === 403) return 'auth_failed';
    if (error.status === 429) return 'rate_limited';
    return 'provider_unavailable';
  }
  if (error instanceof Error) {
    if (error.name === 'AbortError' || error.name === 'TimeoutError') return 'timeout';
    if (error.name === 'ProviderResponseError') return 'invalid_response';
    if (error.name === 'ConfigurationError') return 'not_configured';
    if (/fetch failed|ENOTFOUND|ECONNREFUSED|EAI_AGAIN|socket hang up/i.test(error.message)) {
      return 'provider_unavailable';
    }
  }
  return 'provider_unavailable';
}

/** Raised when a provider response fails schema validation. */
export class ProviderResponseError extends Error {
  constructor(detail: string) {
    super(detail);
    this.name = 'ProviderResponseError';
  }
}

/** Raised when a provider is not configured; distinct from "provider is down". */
export class ConfigurationError extends Error {
  constructor(detail: string) {
    super(detail);
    this.name = 'ConfigurationError';
  }
}

/**
 * Run one provider call under the full policy: rate limit, circuit breaker,
 * timeout, bounded retry with backoff.
 */
export async function attempt<T>(
  operation: (signal: AbortSignal) => Promise<T>,
  options: {
    policy?: Partial<ResiliencePolicy>;
    limiter?: RateLimiter;
    breaker?: CircuitBreaker;
    dependencies?: AttemptDependencies;
  } = {},
): Promise<AttemptResult<T>> {
  const policy: ResiliencePolicy = { ...DEFAULT_POLICY, ...options.policy };
  const sleep = options.dependencies?.sleep ?? defaultSleep;
  const now = options.dependencies?.now ?? Date.now;
  const limiter = options.limiter ?? new RateLimiter(policy.rateLimitPerMinute);
  const breaker = options.breaker ?? new CircuitBreaker(policy.circuitFailureThreshold, policy.circuitCooldownMs);

  if (!breaker.allows(now())) {
    return { ok: false, reason: 'circuit_open', detail: 'the provider circuit is open', attempts: 0 };
  }

  let attempts = 0;
  let lastReason: FailureReason = 'provider_unavailable';
  let lastDetail = 'provider call failed';

  for (let attemptIndex = 0; attemptIndex <= policy.retries; attemptIndex += 1) {
    if (!limiter.tryAcquire(now())) {
      return { ok: false, reason: 'rate_limited', detail: 'provider rate limit reached', attempts };
    }
    attempts += 1;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), policy.timeoutMs);
    try {
      const value = await Promise.race([
        operation(controller.signal),
        new Promise<never>((_resolve, reject) => {
          controller.signal.addEventListener('abort', () => {
            const error = new Error('provider call timed out');
            error.name = 'TimeoutError';
            reject(error);
          });
        }),
      ]);
      breaker.recordSuccess();
      return { ok: true, value };
    } catch (error) {
      lastReason = classifyError(error);
      lastDetail = error instanceof Error ? error.name : 'unknown error';
      breaker.recordFailure(now());
      // A rate-limited or unauthenticated provider will not recover from an
      // immediate retry: stop and report the reason.
      if (lastReason === 'rate_limited' || lastReason === 'auth_failed' || lastReason === 'not_configured') {
        break;
      }
      if (attemptIndex < policy.retries) {
        await sleep(Math.min(2000, 50 * 2 ** attemptIndex));
      }
    } finally {
      clearTimeout(timer);
    }
  }

  return { ok: false, reason: lastReason, detail: lastDetail, attempts };
}
