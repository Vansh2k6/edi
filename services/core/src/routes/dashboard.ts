import { createHash } from 'node:crypto';
import { existsSync, readFileSync, statSync } from 'node:fs';
import { join, normalize, resolve, sep } from 'node:path';
import type { FastifyInstance, onRequestAsyncHookHandler } from 'fastify';

/**
 * Static dashboard shell (W8.8).
 *
 * Serves the built SPA from disk with a strict, first-party-only CSP: no
 * third-party script, no inline handlers, no framing. The no-telemetry rule
 * is structural - the CSP itself blocks the classes of endpoints an
 * analytics or error-reporting SDK would call - and the security headers ride
 * on every response.
 *
 * Assets are read by allowlisted extension from a fixed directory with
 * traversal normalized and re-checked, so a crafted path cannot escape it.
 */

const CSP = [
  "default-src 'self'",
  "script-src 'self'",
  "style-src 'self'",
  "img-src 'self' data:",
  "connect-src 'self'",
  "font-src 'self'",
  "object-src 'none'",
  "base-uri 'none'",
  "form-action 'self'",
  "frame-ancestors 'none'",
].join('; ');

const ALLOWED_EXTENSIONS = new Set(['.html', '.js', '.css', '.svg', '.png', '.ico', '.txt', '.map']);

export interface DashboardStaticOptions {
  /** The directory the dashboard build wrote (its `dist`). */
  distDir: string;
}

function isInsideDir(root: string, candidate: string): boolean {
  const relative = candidate.slice(root.length);
  return relative.startsWith(sep) || relative === '';
}

function serveFile(
  reply: { header: (n: string, v: string) => unknown; code: (n: number) => { send: (b: Buffer) => unknown } },
  file: string,
  contentType: string,
): unknown {
  const body = readFileSync(file);
  reply.header('content-type', contentType);
  reply.header('content-length', String(body.byteLength));
  const etag = createHash('sha256').update(body).digest('hex').slice(0, 16);
  reply.header('etag', `"${etag}"`);
  return reply.code(200).send(body);
}

export function registerDashboardStaticRoutes(app: FastifyInstance, options: DashboardStaticOptions): void {
  const root = resolve(options.distDir);
  const shell = join(root, 'index.html');
  if (!existsSync(shell)) {
    // The dashboard build is not part of this deployment: an explicit 404
    // beats a broken shell.
    app.get('/', (_request, reply) => reply.status(404).send({ error: 'dashboard_not_built' }));
    return;
  }

  const securityHeaders: onRequestAsyncHookHandler = async (_request, reply): Promise<void> => {
    reply.header('content-security-policy', CSP);
    reply.header('x-frame-options', 'DENY');
    reply.header('cross-origin-opener-policy', 'same-origin');
    reply.header('cross-origin-resource-policy', 'same-origin');
  };

  app.get('/', { preHandler: securityHeaders }, (_request, reply) => serveFile(reply, shell, 'text/html; charset=utf-8'));

  app.get<{ Params: { '*': string } }>('/assets/*', { preHandler: securityHeaders }, (request, reply) => {
    const requested = request.params['*'] ?? '';
    let decoded: string;
    try {
      decoded = decodeURIComponent(requested);
    } catch {
      return reply.status(400).send({ error: 'bad_request' });
    }
    if (decoded.includes('\0') || decoded.includes('\\')) {
      return reply.status(400).send({ error: 'bad_request' });
    }
    const candidate = normalize(join(root, decoded));
    if (!isInsideDir(root, candidate)) {
      return reply.status(404).send({ error: 'not_found' });
    }
    const dot = candidate.lastIndexOf('.');
    const ext = dot < 0 ? '' : candidate.slice(dot).toLowerCase();
    if (!ALLOWED_EXTENSIONS.has(ext) || !existsSync(candidate) || !statSync(candidate).isFile()) {
      return reply.status(404).send({ error: 'not_found' });
    }
    const types: Record<string, string> = {
      '.html': 'text/html; charset=utf-8',
      '.js': 'text/javascript; charset=utf-8',
      '.css': 'text/css; charset=utf-8',
      '.svg': 'image/svg+xml',
      '.png': 'image/png',
      '.ico': 'image/x-icon',
      '.txt': 'text/plain; charset=utf-8',
      '.map': 'application/json',
    };
    return serveFile(reply, candidate, types[ext] ?? 'application/octet-stream');
  });

  // SPA fallback: any other path renders the shell; the client router decides
  // whether it is a route or a 404 view. API and asset namespaces keep their
  // JSON 404 - an unknown API route must never answer with HTML.
  app.get<{ Params: { '*': string } }>('*', { preHandler: securityHeaders }, (request, reply) => {
    const path = request.url.split('?')[0] ?? request.url;
    if (path.startsWith('/api/') || path.startsWith('/api') || path.startsWith('/assets/')) {
      return reply.status(404).send({ error: 'not_found' });
    }
    return serveFile(reply, shell, 'text/html; charset=utf-8');
  });
}
