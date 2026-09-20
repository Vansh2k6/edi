import { createHash, createHmac, randomUUID, timingSafeEqual } from 'node:crypto';
import { z } from 'zod';
import type { FastifyInstance } from 'fastify';
import type { SessionProvider } from './session.js';

/**
 * Web session and CSRF (W8.1).
 *
 * The dashboard authenticates through an httpOnly, SameSite=Lax cookie issued
 * here - never through `localStorage` (the plan bans tokens there). The token
 * is HMAC-signed and stateless; the CSRF token is derived from the same
 * secret and the session's id, so a stolen CSRF token alone is useless and a
 * session forged without the secret fails the signature check first.
 *
 * Real token/session hardening (rotation, revocation lists, WebAuthn) is
 * Phase 15 work; this module provides the prototype's honest baseline.
 */

export const SESSION_COOKIE = 'pv_session';
export const CSRF_COOKIE = 'pv_csrf';
export const CSRF_HEADER = 'x-pv-csrf';

interface SessionPayload {
  user_id: string;
  jti: string;
  /** Expiry, epoch milliseconds. */
  exp: number;
}

function b64url(input: Buffer | string): string {
  return Buffer.from(input).toString('base64url');
}

function hmac(payload: string, secret: string): string {
  return createHmac('sha256', secret).update(payload).digest('base64url');
}

/** Length-independent constant-time string comparison. */
export function timingSafeStringEqual(a: string, b: string): boolean {
  const ha = createHash('sha256').update(a).digest();
  const hb = createHash('sha256').update(b).digest();
  return timingSafeEqual(ha, hb);
}

export interface IssuedSession {
  token: string;
  jti: string;
  expiresAt: Date;
  csrfToken: string;
}

export function issueSession(
  sessionSecret: string,
  userId: string,
  ttlSeconds: number,
  now: Date = new Date(),
): IssuedSession {
  const payload: SessionPayload = { user_id: userId, jti: randomUUID(), exp: now.getTime() + ttlSeconds * 1000 };
  const body = b64url(JSON.stringify(payload));
  const token = `${body}.${hmac(body, sessionSecret)}`;
  return { token, jti: payload.jti, expiresAt: new Date(payload.exp), csrfToken: csrfTokenFor(sessionSecret, payload.jti) };
}

export function csrfTokenFor(sessionSecret: string, jti: string): string {
  return hmac(`csrf:${jti}`, sessionSecret);
}

/** Verify signature and expiry; anything odd is null, never an error shape. */
export function verifySessionToken(sessionSecret: string, token: string, now: Date = new Date()): SessionPayload | null {
  const dot = token.indexOf('.');
  if (dot <= 0) return null;
  const body = token.slice(0, dot);
  const mac = token.slice(dot + 1);
  const expected = hmac(body, sessionSecret);
  if (!timingSafeStringEqual(mac, expected)) return null;
  try {
    const payload = JSON.parse(Buffer.from(body, 'base64url').toString()) as SessionPayload;
    if (typeof payload.user_id !== 'string' || typeof payload.jti !== 'string' || typeof payload.exp !== 'number') return null;
    if (payload.exp <= now.getTime()) return null;
    return payload;
  } catch {
    return null;
  }
}

/**
 * Revoked session ids. A stateless cookie cannot un-issue itself, so logout
 * records the session's `jti` here and every verify path refuses it. Entries
 * expire with their session, so the map self-prunes as it grows.
 */
export interface SessionRevocations {
  revoked(jti: string): boolean;
  revoke(jti: string, expiresAtMs: number): void;
}

export function createMemoryRevocations(): SessionRevocations {
  const entries = new Map<string, number>();
  return {
    revoked: (jti) => entries.has(jti),
    revoke: (jti, expiresAtMs) => {
      entries.set(jti, expiresAtMs);
      if (entries.size > 4096) {
        const nowMs = Date.now();
        for (const [id, exp] of entries) {
          if (exp <= nowMs) entries.delete(id);
        }
        while (entries.size > 4096) {
          const oldest = entries.keys().next().value;
          if (oldest === undefined) break;
          entries.delete(oldest);
        }
      }
    },
  };
}

export function parseCookieHeader(header: string | undefined): Record<string, string> {
  if (header === undefined || header === '') return {};
  const out: Record<string, string> = {};
  for (const part of header.split(';')) {
    const eq = part.indexOf('=');
    if (eq <= 0) continue;
    const name = part.slice(0, eq).trim();
    const value = part.slice(eq + 1).trim();
    try {
      out[name] = decodeURIComponent(value);
    } catch {
      out[name] = value;
    }
  }
  return out;
}

function serializeCookie(name: string, value: string, options: { maxAgeSeconds: number; secure: boolean; httpOnly: boolean }): string {
  const parts = [`${name}=${encodeURIComponent(value)}`, 'Path=/', `Max-Age=${options.maxAgeSeconds}`, 'SameSite=Lax'];
  if (options.httpOnly) parts.push('HttpOnly');
  if (options.secure) parts.push('Secure');
  return parts.join('; ');
}

export function sessionCookie(token: string, maxAgeSeconds: number, secure: boolean): string {
  return serializeCookie(SESSION_COOKIE, token, { maxAgeSeconds, secure, httpOnly: true });
}

export function csrfCookie(token: string, maxAgeSeconds: number, secure: boolean): string {
  return serializeCookie(CSRF_COOKIE, token, { maxAgeSeconds, secure, httpOnly: false });
}

/** Expired cookies: the same attributes so every browser drops them. */
export function clearedCookies(secure: boolean): string[] {
  return [serializeCookie(SESSION_COOKIE, '', { maxAgeSeconds: 0, secure, httpOnly: true }), serializeCookie(CSRF_COOKIE, '', { maxAgeSeconds: 0, secure, httpOnly: false })];
}

/**
 * A session provider that resolves the signed cookie. It composes with the
 * route layer exactly like the other providers: `resolve` returns the
 * identity or null, and routes stay identical.
 */
export function createCookieSessionProvider(options: {
  sessionSecret: string;
  ttlSeconds?: number;
  revocations?: SessionRevocations;
  now?: () => Date;
}): SessionProvider & { kind: 'cookie' } {
  const now = options.now ?? (() => new Date());
  return {
    kind: 'cookie',
    resolve: (headers) => {
      const cookieHeader = Array.isArray(headers.cookie) ? headers.cookie[0] : headers.cookie;
      const cookies = parseCookieHeader(cookieHeader);
      const token = cookies[SESSION_COOKIE];
      if (token === undefined) return Promise.resolve(null);
      const payload = verifySessionToken(options.sessionSecret, token, now());
      if (payload === null) return Promise.resolve(null);
      if (options.revocations?.revoked(payload.jti)) return Promise.resolve(null);
      return Promise.resolve({ user_id: payload.user_id, actor: 'owner' as const, device_key_id: null });
    },
  };
}

export const loginRequestSchema = z.strictObject({ owner_secret: z.string().min(1).max(256) });

/**
 * Fixed-window throttle for the login route.
 *
 * The owner secret is the only dashboard credential, so an unthrottled endpoint
 * would allow an online guessing loop. Refused requests are counted per window;
 * once the limit is reached the secret is not even compared until the window
 * expires, and a successful login clears the count. Blocked requests do not
 * extend the window, so a legitimate owner regains access promptly.
 */
export interface LoginThrottle {
  /** True when attempts are refused outright for this window. */
  blocked(): boolean;
  /** Record one failed attempt. */
  fail(): void;
  /** Clear the count after a success. */
  reset(): void;
}

export function createLoginThrottle(options: { maxFailures: number; windowMs: number; now?: () => Date }): LoginThrottle {
  const now = options.now ?? (() => new Date());
  let windowStart = now().getTime();
  let failures = 0;
  return {
    blocked() {
      if (now().getTime() - windowStart >= options.windowMs) {
        windowStart = now().getTime();
        failures = 0;
      }
      return failures >= options.maxFailures;
    },
    fail() {
      if (now().getTime() - windowStart >= options.windowMs) {
        windowStart = now().getTime();
        failures = 0;
      }
      failures += 1;
    },
    reset() {
      failures = 0;
    },
  };
}

export interface SessionRouteOptions {
  sessionSecret: string;
  ownerSecret: string;
  /** The one owner id this deployment's dashboard represents. */
  ownerUserId: string;
  ttlSeconds?: number;
  /** Logout records the presented session's id here so its cookie stops working. */
  revocations?: SessionRevocations;
  /** `Secure` cookies are dropped on plain http, so only production sets them. */
  secureCookie: boolean;
  /** Brute-force ceiling for `/api/session/login`; defaults to 5 failures per minute. */
  loginThrottle?: { maxFailures: number; windowMs: number };
  now?: () => Date;
}

/** Login, logout and the session bootstrap endpoint the dashboard calls on load. */
export function registerSessionRoutes(app: FastifyInstance, options: SessionRouteOptions): void {
  const ttlSeconds = options.ttlSeconds ?? 12 * 60 * 60;
  const now = options.now ?? (() => new Date());
  const throttle = createLoginThrottle({
    maxFailures: options.loginThrottle?.maxFailures ?? 5,
    windowMs: options.loginThrottle?.windowMs ?? 60_000,
    now,
  });

  app.post('/api/session/login', async (request, reply) => {
    const parsed = loginRequestSchema.safeParse(request.body);
    if (!parsed.success) {
      return reply.status(400).send({ error: 'invalid_request', fields: parsed.error.issues.map((issue) => issue.path.join('.')) });
    }
    // Checked before the secret comparison: once the window is exhausted the
    // endpoint answers 429 without doing credential work for the caller.
    if (throttle.blocked()) {
      return reply.status(429).send({ error: 'too_many_attempts' });
    }
    if (!timingSafeStringEqual(parsed.data.owner_secret, options.ownerSecret)) {
      throttle.fail();
      return reply.status(401).send({ error: 'invalid_credentials' });
    }
    throttle.reset();
    const userId = options.ownerUserId;
    const issued = issueSession(options.sessionSecret, userId, ttlSeconds, now());
    reply.header('set-cookie', [sessionCookie(issued.token, ttlSeconds, options.secureCookie), csrfCookie(issued.csrfToken, ttlSeconds, options.secureCookie)]);
    return reply.send({ user_id: userId, csrf_token: issued.csrfToken, expires_at: issued.expiresAt.toISOString() });
  });

  app.post('/api/session/logout', async (request, reply) => {
    // A cleared cookie is not enough: a copied token must die too, so logout
    // revokes the presented session's id for the remainder of its lifetime.
    const cookies = parseCookieHeader(request.headers.cookie);
    const token = cookies[SESSION_COOKIE];
    if (token !== undefined) {
      const payload = verifySessionToken(options.sessionSecret, token, now());
      if (payload !== null) options.revocations?.revoke(payload.jti, payload.exp);
    }
    reply.header('set-cookie', clearedCookies(options.secureCookie));
    return reply.status(204).send();
  });

  app.get('/api/session', async (request, reply) => {
    const cookies = parseCookieHeader(request.headers.cookie);
    const token = cookies[SESSION_COOKIE];
    const payload = token === undefined ? null : verifySessionToken(options.sessionSecret, token, now());
    if (payload === null) return reply.status(401).send({ error: 'session_expired' });
    return reply.send({ user_id: payload.user_id, csrf_token: csrfTokenFor(options.sessionSecret, payload.jti) });
  });
}

const MUTATING = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

/**
 * Double-submit CSRF guard for cookie sessions.
 *
 * Only requests that present a *valid session cookie* are guarded: the
 * device-signed extension API has no cookie and no CSRF exposure. A mutating
 * request with a valid session but without the matching `x-pv-csrf` header is
 * refused before any handler runs.
 */
export function registerCsrfGuard(app: FastifyInstance, options: { sessionSecret: string; revocations?: SessionRevocations; now?: () => Date }): void {
  const now = options.now ?? (() => new Date());
  app.addHook('preHandler', async (request, reply) => {
    if (!MUTATING.has(request.method)) return;
    const url = request.url.split('?')[0] ?? request.url;
    if (!url.startsWith('/api/')) return;
    const cookies = parseCookieHeader(request.headers.cookie);
    const token = cookies[SESSION_COOKIE];
    if (token === undefined) return;
    const payload = verifySessionToken(options.sessionSecret, token, now());
    if (payload === null) return; // unauthenticated: the auth layer answers 401
    if (options.revocations?.revoked(payload.jti)) return; // logged out: the auth layer answers 401
    const presented = request.headers[CSRF_HEADER];
    const headerValue = Array.isArray(presented) ? presented[0] : presented;
    if (headerValue === undefined) {
      return reply.status(403).send({ error: 'csrf_required' });
    }
    if (!timingSafeStringEqual(headerValue, csrfTokenFor(options.sessionSecret, payload.jti))) {
      return reply.status(403).send({ error: 'csrf_mismatch' });
    }
  });
}
