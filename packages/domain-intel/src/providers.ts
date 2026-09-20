import { lookup as dnsLookup, resolve4, resolveMx, resolveTxt } from 'node:dns/promises';
import { z } from 'zod';
import { signalSchema, type DomainSignal } from '@pv/schemas';
import {
  ConfigurationError,
  ProviderResponseError,
} from './resilience.js';
import { isNonPublicHost } from '@pv/schemas';
import { sourceLabel, type DomainIntelligenceProvider, type ProviderContext } from './provider.js';

const MS_PER_DAY = 86_400_000;

function ageDaysFrom(iso: string, now: Date): number | null {
  const parsed = Date.parse(iso);
  if (Number.isNaN(parsed)) return null;
  const days = Math.floor((now.getTime() - parsed) / MS_PER_DAY);
  if (days < 0) return null; // a future creation date is quarantined, not trusted
  return days;
}

/* ------------------------------------------------------------------ RDAP --- */

/** Only the fields this provider uses; an unexpected shape is rejected. */
const rdapEventsSchema = z.object({
  events: z
    .array(z.object({ eventAction: z.string().max(64), eventDate: z.string().max(64) }))
    .max(64)
    .optional(),
});

export interface HttpProviderOptions {
  endpoint: string;
  token?: string;
  fetchImpl?: typeof fetch;
  /** Provider id used in the signal `source`. */
  providerId?: string;
}

/** Registration date via RDAP, from which the domain age is derived. */
export class RdapRegistrationProvider implements DomainIntelligenceProvider {
  readonly provider_id = 'rdap';
  readonly produces = ['registration', 'domain_age'] as const;
  readonly #endpoint: string;
  readonly #fetch: typeof fetch;

  constructor(options: HttpProviderOptions) {
    this.#endpoint = options.endpoint;
    this.#fetch = options.fetchImpl ?? fetch;
  }

  async lookup(context: ProviderContext): Promise<DomainSignal> {
    if (isNonPublicHost(context.host)) {
      return signalSchema.parse({
        type: 'registration',
        value: null,
        source: sourceLabel(this.provider_id, 'skipped'),
        retrieved_at: context.now.toISOString(),
        freshness: 'unknown',
        confidence: 0,
        unknown_reason: 'non-public hosts are not sent to external providers',
        age_days: null,
      });
    }
    const url = `${this.#endpoint.replace(/\/$/, '')}/domain/${encodeURIComponent(context.host)}`;
    const response = await this.#fetch(url, {
      signal: context.signal,
      headers: { accept: 'application/rdap+json, application/json' },
    });
    if (!response.ok) {
      throw response;
    }
    const parsed = rdapEventsSchema.safeParse(await response.json());
    if (!parsed.success || !parsed.data.events) {
      throw new ProviderResponseError('rdap response did not match the expected shape');
    }
    const registration = parsed.data.events.find(
      (event) => event.eventAction.toLowerCase() === 'registration',
    );
    if (!registration) {
      return signalSchema.parse({
        type: 'registration',
        value: null,
        source: sourceLabel(this.provider_id, 'registry'),
        retrieved_at: context.now.toISOString(),
        freshness: 'unknown',
        confidence: 0,
        unknown_reason: 'the registry returned no registration event',
        age_days: null,
      });
    }
    const age = ageDaysFrom(registration.eventDate, context.now);
    return signalSchema.parse({
      type: age === null ? 'registration' : 'domain_age',
      value: age === null ? registration.eventDate : age,
      source: sourceLabel(this.provider_id, 'registry'),
      retrieved_at: context.now.toISOString(),
      freshness: 'fresh',
      confidence: age === null ? 0.5 : 0.9,
      unknown_reason: null,
      age_days: age,
    });
  }
}

/* ------------------------------------------------------------------- DNS --- */

/** Presence and record counts only - never the addresses themselves. */
export class DnsSignalProvider implements DomainIntelligenceProvider {
  readonly provider_id = 'dns';
  readonly produces = ['dns'] as const;

  constructor(
    private readonly resolvers: {
      resolve4: typeof resolve4;
      resolveMx: typeof resolveMx;
      resolveTxt: typeof resolveTxt;
      lookup: typeof dnsLookup;
    } = { resolve4, resolveMx, resolveTxt, lookup: dnsLookup },
  ) {}

  async lookup(context: ProviderContext): Promise<DomainSignal> {
    const counts = await Promise.all(
      ([this.resolvers.resolve4, this.resolvers.resolveMx] as const).map(async (resolver) => {
        try {
          const records = await resolver(context.host);
          return records.length;
        } catch {
          return 0;
        }
      }),
    );
    const [aRecords = 0, mxRecords = 0] = counts;
    const resolvable = aRecords > 0 || mxRecords > 0;
    // An unresolvable name is `unknown` with zero confidence - it is not evidence
    // that the name is safe, and it is not a resolved "no records" answer either.
    return signalSchema.parse({
      type: 'dns',
      value: resolvable ? `A:${aRecords > 0 ? 'yes' : 'no'},MX:${mxRecords > 0 ? 'yes' : 'no'}` : null,
      source: sourceLabel(this.provider_id, 'resolver'),
      retrieved_at: context.now.toISOString(),
      freshness: resolvable ? 'fresh' : 'unknown',
      confidence: resolvable ? 0.8 : 0,
      unknown_reason: resolvable ? null : 'the name did not resolve to any address or mail exchange',
      age_days: null,
    });
  }
}

/* -------------------------------------------------- Certificate history --- */

const crtShEntrySchema = z.array(z.object({ not_before: z.string().max(64) }).passthrough()).max(500);

/** Certificate transparency history: earliest and latest observation only. */
export class CertificateHistoryProvider implements DomainIntelligenceProvider {
  readonly provider_id = 'ct';
  readonly produces = ['certificate_history'] as const;
  readonly #endpoint: string | undefined;
  readonly #fetch: typeof fetch;

  constructor(options: { endpoint?: string; fetchImpl?: typeof fetch } = {}) {
    this.#endpoint = options.endpoint;
    this.#fetch = options.fetchImpl ?? fetch;
  }

  async lookup(context: ProviderContext): Promise<DomainSignal> {
    if (this.#endpoint === undefined) {
      throw new ConfigurationError('no certificate transparency endpoint is configured');
    }
    const url = `${this.#endpoint.replace(/\/$/, '')}/?q=%25.${encodeURIComponent(context.host)}&output=json`;
    const response = await this.#fetch(url, { signal: context.signal, headers: { accept: 'application/json' } });
    if (!response.ok) throw response;
    const parsed = crtShEntrySchema.safeParse(await response.json());
    if (!parsed.success) throw new ProviderResponseError('certificate transparency response had an unexpected shape');
    if (parsed.data.length === 0) {
      return signalSchema.parse({
        type: 'certificate_history',
        value: null,
        source: sourceLabel(this.provider_id, 'ct-log'),
        retrieved_at: context.now.toISOString(),
        freshness: 'unknown',
        confidence: 0,
        unknown_reason: 'no certificate was found in the transparency log for this name',
        age_days: null,
      });
    }
    const dates = parsed.data
      .map((entry) => Date.parse(entry.not_before))
      .filter((value) => !Number.isNaN(value))
      .sort((a, b) => a - b);
    const first = dates[0];
    if (first === undefined) {
      throw new ProviderResponseError('certificate entries carried no usable timestamps');
    }
    return signalSchema.parse({
      type: 'certificate_history',
      value: `first_seen:${new Date(first).toISOString().slice(0, 10)},count:${dates.length}`,
      source: sourceLabel(this.provider_id, 'ct-log'),
      retrieved_at: context.now.toISOString(),
      freshness: 'fresh',
      confidence: 0.7,
      unknown_reason: null,
      age_days: ageDaysFrom(new Date(first).toISOString(), context.now),
    });
  }
}

/* ----------------------------------------------------------- Reputation --- */

const reputationResponseSchema = z.object({
  verdict: z.enum(['trusted', 'neutral', 'suspicious', 'malicious', 'unknown']),
  confidence: z.number().min(0).max(1),
  abuse_reports: z.number().int().min(0).max(1_000_000),
  categories: z.array(z.string().max(64)).max(20).optional(),
});

/**
 * External reputation and abuse signals.
 *
 * The provider is untrusted: its response is validated, its verdict is recorded
 * as an input, and a missing or invalid response becomes `unknown` rather than a
 * benign value (D-018).
 */
export class ReputationProvider implements DomainIntelligenceProvider {
  readonly provider_id = 'reputation';
  readonly produces = ['reputation', 'abuse'] as const;
  readonly #endpoint: string | undefined;
  readonly #token: string | undefined;
  readonly #fetch: typeof fetch;

  constructor(options: { endpoint?: string; token?: string; fetchImpl?: typeof fetch } = {}) {
    this.#endpoint = options.endpoint;
    this.#token = options.token;
    this.#fetch = options.fetchImpl ?? fetch;
  }

  async lookup(context: ProviderContext): Promise<DomainSignal> {
    if (this.#endpoint === undefined || this.#token === undefined) {
      throw new ConfigurationError('no reputation provider endpoint or token is configured');
    }
    const url = `${this.#endpoint.replace(/\/$/, '')}/lookup?host=${encodeURIComponent(context.host)}`;
    const response = await this.#fetch(url, {
      signal: context.signal,
      headers: { accept: 'application/json', authorization: `Bearer ${this.#token}` },
    });
    if (!response.ok) throw response;
    const parsed = reputationResponseSchema.safeParse(await response.json());
    if (!parsed.success) throw new ProviderResponseError('reputation response failed schema validation');
    const { verdict, confidence } = parsed.data;
    if (verdict === 'unknown') {
      return signalSchema.parse({
        type: 'reputation',
        value: null,
        source: sourceLabel(this.provider_id, 'external'),
        retrieved_at: context.now.toISOString(),
        freshness: 'unknown',
        confidence: 0,
        unknown_reason: 'the provider returned no verdict for this host',
        age_days: null,
      });
    }
    return signalSchema.parse({
      type: 'reputation',
      value: verdict,
      source: sourceLabel(this.provider_id, 'external'),
      retrieved_at: context.now.toISOString(),
      freshness: 'fresh',
      confidence,
      unknown_reason: null,
      age_days: null,
    });
  }
}

/* --------------------------------------------------------------- helpers --- */


