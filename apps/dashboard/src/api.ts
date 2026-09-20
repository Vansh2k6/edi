/**
 * Dashboard API client (W8.1).
 *
 * Thin typed wrappers over `fetch` with two rules: the session cookie is the
 * only credential (never `localStorage`), and every mutating call carries the
 * CSRF token the login/session bootstrap returned. Error responses are
 * returned as `{ error }` bodies, never thrown past the view layer.
 */

export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  constructor(status: number, code: string) {
    super(code);
    this.status = status;
    this.code = code;
  }
}

let csrfToken: string | null = null;

export function setCsrfToken(token: string | null): void {
  csrfToken = token;
}

async function request(path: string, options: { method?: string; body?: unknown } = {}): Promise<unknown> {
  const headers: Record<string, string> = { accept: 'application/json' };
  if (options.body !== undefined) headers['content-type'] = 'application/json';
  if (csrfToken !== null && options.method !== undefined && options.method !== 'GET') {
    headers['x-pv-csrf'] = csrfToken;
  }
  const response = await fetch(path, {
    method: options.method ?? 'GET',
    headers,
    credentials: 'same-origin',
    ...(options.body === undefined ? {} : { body: JSON.stringify(options.body) }),
  });
  if (response.status === 204) return null;
  const text = await response.text();
  const parsed: unknown = text === '' ? null : JSON.parse(text);
  if (!response.ok) {
    const code =
      typeof parsed === 'object' && parsed !== null && 'error' in parsed && typeof (parsed as { error: unknown }).error === 'string'
        ? (parsed as { error: string }).error
        : typeof parsed === 'object' && parsed !== null && 'reason' in parsed && typeof (parsed as { reason: unknown }).reason === 'string'
          ? (parsed as { reason: string }).reason
          : 'request_failed';
    if (response.status === 401 && code === 'session_expired') {
      // Session expiry mid-flow: surface as a typed error the router turns
      // into a redirect that preserves no partial mutation.
      throw new ApiError(401, 'session_expired');
    }
    throw new ApiError(response.status, code);
  }
  return parsed;
}

function get<T>(path: string): Promise<T> {
  return request(path) as Promise<T>;
}

function send<T>(method: string, path: string, body?: unknown): Promise<T> {
  return request(path, { method, ...(body === undefined ? {} : { body }) }) as Promise<T>;
}

export interface SessionBootstrap {
  user_id: string;
  csrf_token: string;
}

export const api = {
  login: (ownerSecret: string) => send<SessionBootstrap>('POST', '/api/session/login', { owner_secret: ownerSecret }),
  logout: () => send<null>('POST', '/api/session/logout'),
  session: () => get<SessionBootstrap>('/api/session'),

  listDecisions: (limit: number, before: string | null) =>
    get<{ decisions: unknown[]; next_cursor: string | null }>(
      `/api/decisions?limit=${limit}${before === null ? '' : `&before=${encodeURIComponent(before)}`}`,
    ),
  getDecision: (id: string) => get<unknown>(`/api/decisions/${id}`),

  listConsents: () => get<{ consents: unknown[] }>('/api/consents'),
  previewConsent: (categoryId: string) => send<unknown>('POST', '/api/consents/preview', { data_category_id: categoryId }),
  grantConsent: (categoryId: string) => send<{ consent: unknown }>('POST', '/api/consents', { data_category_id: categoryId }),
  revokeConsent: (categoryId: string) => send<null>('DELETE', `/api/consents/${categoryId}`),

  listEntries: () => get<{ entries: unknown[] }>('/api/vault/entries'),
  revealEntry: (dataId: string, confirm: boolean) => send<unknown>('POST', `/api/vault/entries/${dataId}/reveal`, { confirm }),

  listRules: () => get<{ rules: unknown[] }>('/api/rules'),
  previewRule: (rule: unknown) => send<unknown>('POST', '/api/rules/preview', { rule }),
  createRule: (rule: unknown) => send<{ rule: unknown }>('POST', '/api/rules', { rule }),
  deleteRule: (ruleId: string) => send<null>('DELETE', `/api/rules/${ruleId}`),

  domainIntelligence: (host: string) => send<{ summary: unknown; failures: unknown[] }>('POST', '/api/domain-intelligence', { host }),
};
