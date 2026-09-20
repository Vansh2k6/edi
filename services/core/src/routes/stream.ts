import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import type { SessionProvider } from '../session.js';
import type { DecisionEventBus } from '../event-bus.js';
import { streamDecisions } from '../event-bus.js';
import { requireIdentity, sendValidationFailure } from './support.js';

/**
 * Live decisions over server-sent events (W8.3).
 *
 * The stream is authenticated like every other route - the session provider
 * decides - and each connection receives only its own owner's events. The
 * reply is hijacked: after identity and headers are settled, Fastify's reply
 * lifecycle steps aside and the SSE frames are written straight to the
 * socket until the client disconnects.
 */

const querySchema = z.strictObject({});

export interface StreamRouteDependencies {
  session: SessionProvider;
  bus: DecisionEventBus;
}

export function registerStreamRoutes(app: FastifyInstance, deps: StreamRouteDependencies): void {
  app.get('/api/stream', async (request, reply) => {
    const identity = await requireIdentity(request, reply, deps.session);
    if (!identity) return reply;
    const query = querySchema.safeParse(request.query);
    if (!query.success) return sendValidationFailure(reply, query.error.issues.map((issue) => issue.path.join('.')));

    // Take over the socket: without the hijack Fastify finalizes the reply
    // after the handler returns and replaces the stream's headers with its
    // own (observed live as a text/event-stream vs text/plain clobber).
    reply.hijack();
    // streamDecisions owns the SSE headers and the head is flushed by its
    // first frame. Calling writeHead here as well sent the head twice: the
    // second set threw ERR_HTTP_HEADERS_SENT and the socket hung with no
    // response at all (found in the live browser walkthrough).
    void streamDecisions(reply.raw, deps.bus, identity.user_id);
  });
}
