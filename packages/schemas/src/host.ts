import { originSchema, type Origin, type OriginKind } from './observation.js';

/**
 * Host and origin normalization.
 *
 * This lives in the shared contract package on purpose: the extension derives the
 * origin from trusted browser context and the core re-derives it, and both must
 * agree exactly. Two implementations of this logic would eventually disagree, and
 * the disagreement would be a security hole (AGENT.md: avoid duplicated security
 * logic).
 */

const PRIVATE_V4 = [
  /^10\./,
  /^192\.168\./,
  /^172\.(1[6-9]|2\d|3[01])\./,
  /^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./, // carrier-grade NAT
];

const LOOPBACK_V4 = /^127\./;
const LINK_LOCAL_V4 = /^169\.254\./;
const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/;

export function isIpv4Literal(host: string): boolean {
  return IPV4.test(host);
}

export function isIpv6Literal(host: string): boolean {
  return host.includes(':');
}

/**
 * Classify a host. Internal and non-public origins are first-class outcomes: a
 * localhost request must never be treated as an ordinary public website.
 */
export function originKindFor(host: string): OriginKind {
  const normalized = host.toLowerCase().replace(/\.$/, '');
  if (normalized === '') return 'unknown';
  if (normalized === 'localhost' || normalized.endsWith('.localhost')) return 'localhost';
  if (LOOPBACK_V4.test(normalized)) return 'loopback';
  if (LINK_LOCAL_V4.test(normalized) || normalized.startsWith('fe80:')) return 'link_local';
  if (PRIVATE_V4.some((pattern) => pattern.test(normalized))) return 'private';
  if (isIpv6Literal(normalized)) return 'ip_literal';
  if (isIpv4Literal(normalized)) return 'ip_literal';
  if (normalized.endsWith('.internal') || normalized.endsWith('.local') || normalized.endsWith('.test')) {
    return 'internal';
  }
  if (!normalized.includes('.')) return 'internal';
  return 'public';
}

/** True when a host must never be sent to an external provider. */
export function isNonPublicHost(host: string): boolean {
  const kind = originKindFor(host);
  return kind !== 'public';
}

const TWO_PART_SUFFIXES = new Set([
  'co.uk',
  'org.uk',
  'ac.uk',
  'gov.uk',
  'co.in',
  'net.in',
  'org.in',
  'ac.in',
  'gov.in',
  'co.jp',
  'co.nz',
  'com.au',
  'net.au',
  'org.au',
  'com.br',
  'com.cn',
]);

/**
 * Best-effort registrable domain (eTLD+1).
 *
 * A full public-suffix list is a dependency this phase does not need. Common
 * two-part suffixes are handled explicitly and everything else falls back to the
 * last two labels; callers must treat the result as a hint, not as an authority.
 */
export function registrableDomain(host: string): string | null {
  const normalized = host.toLowerCase().replace(/\.$/, '');
  if (normalized === '' || isNonPublicHost(normalized)) return null;
  const labels = normalized.split('.');
  if (labels.length < 2) return null;
  const lastTwo = labels.slice(-2).join('.');
  if (TWO_PART_SUFFIXES.has(lastTwo) && labels.length >= 3) {
    return labels.slice(-3).join('.');
  }
  return lastTwo;
}

const DEFAULT_PORTS: Record<string, number> = { http: 80, https: 443, ws: 80, wss: 443 };

export interface NormalizeOptions {
  /** Set when the URL came from a chrome-extension:// page. */
  isExtensionPage?: boolean;
  /** The origin the top-level frame reports, used only for display context. */
  topLevelUrl?: string | null;
}

/**
 * Normalize a URL into the origin shape the contracts expect.
 *
 * Throws for a URL that cannot be parsed at all; callers turn that into an
 * explicit `unknown` observation rather than inventing an origin.
 */
export function normalizeOrigin(rawUrl: string, options: NormalizeOptions = {}): Origin {
  const url = new URL(rawUrl);
  const scheme = url.protocol.replace(':', '');
  const hostname = url.hostname.toLowerCase().replace(/\.$/, '');

  if (scheme === 'chrome-extension' || scheme === 'moz-extension') {
    return originSchema.parse({
      raw: rawUrl,
      host: hostname,
      kind: 'extension',
      scheme: 'chrome-extension',
      port: url.port === '' ? null : Number(url.port),
      registrable_domain: null,
      display: hostname,
    });
  }

  const knownScheme = scheme === 'http' || scheme === 'https' || scheme === 'ws' || scheme === 'wss';
  const kind = options.isExtensionPage === true ? 'extension' : originKindFor(hostname);
  const port = url.port === '' ? null : Number(url.port);
  // Default ports are dropped so https://example.com and https://example.com:443 agree.
  const explicitPort = port !== null && DEFAULT_PORTS[scheme] === port ? null : port;

  return originSchema.parse({
    raw: rawUrl,
    host: hostname,
    kind,
    scheme: knownScheme ? scheme : 'other',
    port: explicitPort,
    registrable_domain: registrableDomain(hostname),
    display: hostname,
  });
}

/** Normalize without throwing; returns null when the value is not a URL. */
export function tryNormalizeOrigin(rawUrl: string, options: NormalizeOptions = {}): Origin | null {
  try {
    return normalizeOrigin(rawUrl, options);
  } catch {
    return null;
  }
}
