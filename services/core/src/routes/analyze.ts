import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { observedRequestSchema, type DataCategory } from '@pv/schemas';
import { assessFeasibility, analyzeMinimization, classifyRequest } from '@pv/rules';
import type { SessionProvider } from '../session.js';
import type { DeviceRequestContext } from '../device-auth.js';
import { authenticate, parseBody, sendValidationFailure } from './support.js';

const analyzeRequestSchema = z.strictObject({
  observation: observedRequestSchema,
});

export interface AnalyzeRouteDependencies {
  session: SessionProvider;
  device: DeviceRequestContext;
  categories: readonly DataCategory[];
}

/**
 * Structured facts about a request (`T011`--`T013`).
 *
 * This endpoint deliberately returns no allow/block answer: the analyzer produces
 * facts and the decision engine owns outcomes (ARCHITECTURE.md section 5.4).
 */
export function registerAnalyzeRoutes(app: FastifyInstance, dependencies: AnalyzeRouteDependencies): void {
  const { categories } = dependencies;

  app.post('/api/analyze', async (request, reply) => {
    const authenticated = await authenticate(request, reply, dependencies);
    if (!authenticated) return reply;

    const body = parseBody(authenticated.payload, analyzeRequestSchema);
    if (!body.ok) return sendValidationFailure(reply, body.fields);

    const classification = classifyRequest(body.value.observation, categories);
    const feasibility = assessFeasibility(body.value.observation, classification);
    const minimization = analyzeMinimization(body.value.observation, classification);

    return reply.send({
      request_id: body.value.observation.request_id,
      classification,
      feasibility,
      minimization,
      decision: null,
    });
  });
}
