import type { FastifyReply, FastifyRequest } from 'fastify';
import type { z } from 'zod';
import type { RequestIdentity, SessionProvider } from '../session.js';
import {
  authenticateDeviceRequest,
  isSignedRequest,
  type DeviceAuthFailure,
  type DeviceRequestContext,
} from '../device-auth.js';

export interface AuthenticatedRequest {
  identity: RequestIdentity;
  /**
   * The payload the route may act on: the value inside a verified signature, or
   * the raw body for a request that carried no signature.
   */
  payload: unknown;
  device_key_id: string | null;
}

/**
 * Resolve identity and, when a signature is present or required, prove the body.
 *
 * A body that carries an envelope must verify: accepting it unverified would turn
 * a signing key into decoration. A session that is device-bound must sign even
 * when the caller omits the envelope, so dropping the wrapper is not a way to
 * escape verification.
 */
export async function authenticate(
  request: FastifyRequest,
  reply: FastifyReply,
  dependencies: { session: SessionProvider; device: DeviceRequestContext },
): Promise<AuthenticatedRequest | null> {
  const identity = await requireIdentity(request, reply, dependencies.session);
  if (!identity) return null;

  if (!isSignedRequest(request.body)) {
    if (identity.device_key_id !== null) {
      await reply.status(401).send({ error: 'signature_required' });
      return null;
    }
    return { identity, payload: request.body, device_key_id: null };
  }

  const result = await authenticateDeviceRequest(request.body, identity.user_id, dependencies.device);
  if (!result.ok) {
    await reply.status(401).send({ error: result.reason satisfies DeviceAuthFailure });
    return null;
  }
  if (identity.device_key_id !== null && identity.device_key_id !== result.device_key_id) {
    await reply.status(401).send({ error: 'device_key_mismatch' });
    return null;
  }

  return { identity, payload: result.payload, device_key_id: result.device_key_id };
}

/**
 * Resolve the caller's identity, answering 401 when there is none.
 *
 * Returns null after replying so callers can `return reply` immediately and never
 * continue with an undefined identity.
 */
export async function requireIdentity(
  request: FastifyRequest,
  reply: FastifyReply,
  session: SessionProvider,
): Promise<RequestIdentity | null> {
  const identity = await session.resolve(request.headers);
  if (!identity) {
    await reply.status(401).send({ error: 'authentication_required' });
    return null;
  }
  return identity;
}

export type ParseResult<T> = { ok: true; value: T } | { ok: false; fields: string[] };

/**
 * Validate a body against a strict schema.
 *
 * Failure reports field paths only. A rejected value is never echoed: the body
 * may contain ciphertext, a wrapped key or a secret, and an error response is the
 * easiest place to leak one.
 */
export function parseBody<T>(body: unknown, schema: z.ZodType<T>): ParseResult<T> {
  const parsed = schema.safeParse(body);
  if (parsed.success) return { ok: true, value: parsed.data };
  const fields = new Set<string>();
  for (const issue of parsed.error.issues) {
    // A caller-supplied field the contract does not allow has an empty path, so
    // the offending key names are surfaced explicitly (for example a body that
    // tries to inject "user_id").
    if (issue.code === 'unrecognized_keys') {
      for (const key of issue.keys) fields.add(key);
      continue;
    }
    fields.add(issue.path.map(String).join('.') || '<root>');
  }
  return { ok: false, fields: [...fields] };
}

export function sendValidationFailure(reply: FastifyReply, fields: readonly string[]): FastifyReply {
  return reply.status(400).send({ error: 'invalid_request', fields: [...fields] });
}
