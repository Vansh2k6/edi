import { z } from 'zod';

/**
 * Request identity.
 *
 * `user_id` always comes from here - never from a request body, query string or
 * page-supplied value. Vault routes take the owner from this object, which is why
 * there is no `user_id` parameter anywhere in the route handlers.
 */
export interface RequestIdentity {
  user_id: string;
  actor: 'owner';
  device_key_id: string | null;
}

export interface SessionProvider {
  readonly kind: 'static' | 'dev-header' | 'cookie';
  resolve(headers: Record<string, string | string[] | undefined>): Promise<RequestIdentity | null>;
}

export class SessionUnavailableError extends Error {
  constructor(detail: string) {
    super(detail);
    this.name = 'SessionUnavailableError';
  }
}

// Returns a session provider with a fixed identity (ideal for automated testing and deterministic demos)
export function createStaticSessionProvider(identity: RequestIdentity): SessionProvider {
  return {
    kind: 'static',
    // Resolves immediately to the predetermined request identity
    resolve: () => Promise.resolve(identity),
  };
}

export const DEV_SESSION_HEADER = 'x-pv-dev-user';

/**
 * Development stand-in for real authentication.
 *
 * It reads a header, which is exactly what a real deployment must never do, so it
 * refuses to operate when NODE_ENV is production. Real token or session auth
 * replaces this provider wholesale; the routes do not change.
 */
// Returns a development session provider that extracts user identity from an HTTP header
export function createDevHeaderSessionProvider(options: {
  nodeEnv: string;
  headerName?: string;
}): SessionProvider {
  const headerName = (options.headerName ?? DEV_SESSION_HEADER).toLowerCase();
  return {
    kind: 'dev-header',
    // Resolves request identity from header, strictly throwing in production environments
    resolve: (headers) => {
      if (options.nodeEnv === 'production') {
        throw new SessionUnavailableError(
          'the development header session provider refuses to run in production; configure real authentication',
        );
      }
      const raw = headers[headerName];
      const value = Array.isArray(raw) ? raw[0] : raw;
      if (value === undefined) return Promise.resolve(null);
      const parsed = z.uuid().safeParse(value);
      // Returns validated owner identity if header contains a valid UUID
      return Promise.resolve(
        parsed.success ? { user_id: parsed.data, actor: 'owner', device_key_id: null } : null,
      );
    },
  };
}
