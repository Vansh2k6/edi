import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import type { Config, DataCategory } from '@pv/schemas';
import type { SessionProvider } from '../session.js';
import type { DeviceKeyRegistry } from '../device-auth.js';
import { parseBody, requireIdentity, sendValidationFailure } from './support.js';

const deviceRegistrationSchema = z.strictObject({
  device_key_id: z.string().min(1).max(128),
  /** base64url of the raw Ed25519 public key. */
  public_key: z.string().min(1).max(256),
});

/**
 * Operational and identity routes.
 *
 * `/api/health` reports non-secret configuration facts only: which storage the
 * core is using, and which key provider. It never reports connection strings,
 * tokens or key material.
 */
export function registerMetaRoutes(
  app: FastifyInstance,
  dependencies: {
    session: SessionProvider;
    config: Config;
    categories: readonly DataCategory[];
    repositoryKind: 'memory' | 'postgres';
    cacheKind: 'memory' | 'redis' | 'none';
    providerIds: readonly string[];
    deviceKeys: DeviceKeyRegistry;
    deviceRegistrationEnabled: boolean;
  },
): void {
  const { session, config, categories } = dependencies;

  app.get('/api/health', (_request, reply) =>
    reply.send({
      status: 'ok',
      environment: config.NODE_ENV,
      storage: dependencies.repositoryKind,
      cache: dependencies.cacheKind,
      key_provider: config.KEY_PROVIDER,
      providers: [...dependencies.providerIds],
      categories: categories.length,
    }),
  );

  app.get('/api/categories', (_request, reply) => reply.send({ categories: [...categories] }));

  app.get('/api/me', async (request, reply) => {
    const identity = await requireIdentity(request, reply, session);
    if (!identity) return reply;
    return reply.send(identity);
  });

  // Registration is bound to the authenticated user, so a key can only ever be
  // used to sign for the user who registered it. The route exists only while the
  // development session provider is in use: real authentication replaces both.
  if (!dependencies.deviceRegistrationEnabled) return;
  const { deviceKeys } = dependencies;
  app.post('/api/devices', async (request, reply) => {
    const identity = await requireIdentity(request, reply, session);
    if (!identity) return reply;

    const body = parseBody(request.body, deviceRegistrationSchema);
    if (!body.ok) return sendValidationFailure(reply, body.fields);

    const registered = await deviceKeys.register({
      device_key_id: body.value.device_key_id,
      public_key: body.value.public_key,
      user_id: identity.user_id,
    });
    if (!registered.ok) return reply.status(409).send({ error: registered.reason });
    return reply.status(201).send({ device_key_id: body.value.device_key_id, user_id: identity.user_id });
  });
}
