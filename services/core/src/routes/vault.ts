import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { vaultCreateRequestSchema, type DataCategory } from '@pv/schemas';
import { findCategory } from '../categories.js';
import { rotateUserKey } from '../keys.js';
import type { VaultRepository } from '../repositories/vault-repository.js';
import type { SessionProvider } from '../session.js';
import type { KeyProvider } from '@pv/crypto';
import type { DeviceRequestContext } from '../device-auth.js';
import type { VaultGateway } from '../gateway/authorize.js';
import { authenticate, parseBody, requireIdentity, sendValidationFailure } from './support.js';

export interface VaultRouteDependencies {
  repository: VaultRepository;
  session: SessionProvider;
  /** Uploads accept an optional device signature; reads rely on the session. */
  device: DeviceRequestContext;
  keyProvider: KeyProvider;
  categories: readonly DataCategory[];
  kekRef: string;
  /**
   * The composed gateway is injected here rather than imported: routes must
   * never reach around the disclosure path themselves (T029). Type-only.
   */
  gateway: VaultGateway;
  rulesetVersion: string;
}

/**
 * Vault routes (T007).
 *
 * The owner is always taken from the session. There is deliberately no
 * `user_id` request parameter, and a request that tries to supply one fails
 * schema validation because the body is a strict object.
 */
export function registerVaultRoutes(app: FastifyInstance, dependencies: VaultRouteDependencies): void {
  const { repository, session, keyProvider, categories, kekRef, gateway, rulesetVersion } = dependencies;

  app.post('/api/vault/entries', async (request, reply) => {
    const authenticated = await authenticate(request, reply, dependencies);
    if (!authenticated) return reply;
    const identity = authenticated.identity;

    const body = parseBody(authenticated.payload, vaultCreateRequestSchema);
    if (!body.ok) return sendValidationFailure(reply, body.fields);

    const category = findCategory(categories, body.value.data_category_id);
    if (!category) {
      // An unregistered category is a configuration mismatch, not a client error.
      return reply.status(404).send({ error: 'data_category_not_found' });
    }

    await repository.ensureUser({ user_id: identity.user_id });
    await repository.getOrCreateActiveKey(identity.user_id, kekRef);
    const entry = await repository.createEntry({
      user_id: identity.user_id,
      data_category_id: body.value.data_category_id,
      storage_tier: body.value.storage_tier,
      ciphertext: body.value.ciphertext,
      integrity_digest: body.value.integrity_digest,
      wrapped_dek: body.value.wrapped_dek,
      storage_location: body.value.storage_location ?? null,
      client_metadata: body.value.client_metadata,
    });
    return reply.status(201).send(entry);
  });

  app.get('/api/vault/entries', async (request, reply) => {
    const identity = await requireIdentity(request, reply, session);
    if (!identity) return reply;
    const entries = await repository.listEntries(identity.user_id);
    return reply.send({ entries });
  });

  app.get<{ Params: { data_id: string } }>('/api/vault/entries/:data_id', async (request, reply) => {
    const identity = await requireIdentity(request, reply, session);
    if (!identity) return reply;
    const entry = await repository.getEntry(identity.user_id, request.params.data_id);
    // 404 rather than 403 for someone else's entry: a distinguishable response
    // would confirm that the id exists.
    if (!entry) return reply.status(404).send({ error: 'vault_entry_not_found' });
    return reply.send(entry);
  });

  app.delete<{ Params: { data_id: string } }>('/api/vault/entries/:data_id', async (request, reply) => {
    const identity = await requireIdentity(request, reply, session);
    if (!identity) return reply;
    const deleted = await repository.softDeleteEntry(identity.user_id, request.params.data_id);
    if (!deleted) return reply.status(404).send({ error: 'vault_entry_not_found' });
    return reply.status(204).send();
  });

  app.post('/api/vault/keys/rotate', async (request, reply) => {
    const identity = await requireIdentity(request, reply, session);
    if (!identity) return reply;
    const report = await rotateUserKey({
      repository,
      provider: keyProvider,
      userId: identity.user_id,
      kekRef,
    });
    return reply.send(report);
  });

  // T033 reveal: an explicit gesture plus re-auth confirmation, answered by
  // the gateway so the release is audited and plaintext opens in exactly one
  // place. A local-tier entry answers with an explicit availability state.
  app.post<{ Params: { data_id: string } }>('/api/vault/entries/:data_id/reveal', async (request, reply) => {
    const identity = await requireIdentity(request, reply, session);
    if (!identity) return reply;
    const body = parseBody(request.body, z.strictObject({ confirm: z.boolean().optional() }));
    if (!body.ok) return sendValidationFailure(reply, body.fields);
    const outcome = await gateway.revealForOwner({
      user_id: identity.user_id,
      data_id: request.params.data_id,
      confirm_reauth: body.value.confirm === true,
      policy_version: rulesetVersion,
    });
    if (!outcome.ok) {
      return reply.status(outcome.http_status).send({ error: outcome.failure });
    }
    return reply.send(outcome.result);
  });
}
