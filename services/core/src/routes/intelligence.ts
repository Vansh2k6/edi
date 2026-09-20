import type { FastifyInstance } from 'fastify';
import { intelligenceRequestSchema } from '@pv/schemas';
import {
  collectIntelligence,
  type DomainIntelligenceProvider,
  type IntelligenceCache,
  type ProviderRuntimeState,
} from '@pv/domain-intel';
import type { SessionProvider } from '../session.js';
import type { DeviceRequestContext } from '../device-auth.js';
import { authenticate, parseBody, sendValidationFailure } from './support.js';

export interface IntelligenceRouteDependencies {
  session: SessionProvider;
  device: DeviceRequestContext;
  providers: readonly DomainIntelligenceProvider[];
  cache: IntelligenceCache;
  state: ProviderRuntimeState;
  window: { staleAfterSeconds: number; ttlSeconds: number };
  policy: {
    timeoutMs: number;
    retries: number;
    rateLimitPerMinute: number;
    circuitFailureThreshold: number;
    circuitCooldownMs: number;
  };
}

/**
 * Domain intelligence for an origin (`T014`--`T018`).
 *
 * The response always carries freshness for every signal and an explicit reason
 * for anything that could not be resolved, so a caller can never mistake missing
 * intelligence for a clean result.
 */
export function registerIntelligenceRoutes(app: FastifyInstance, dependencies: IntelligenceRouteDependencies): void {
  app.post('/api/domain-intelligence', async (request, reply) => {
    const authenticated = await authenticate(request, reply, dependencies);
    if (!authenticated) return reply;

    const body = parseBody(authenticated.payload, intelligenceRequestSchema);
    if (!body.ok) return sendValidationFailure(reply, body.fields);

    const result = await collectIntelligence({
      host: body.value.host,
      providers: dependencies.providers,
      cache: dependencies.cache,
      state: dependencies.state,
      window: dependencies.window,
      policy: dependencies.policy,
    });

    return reply.send({ summary: result.summary, failures: result.failures });
  });
}
