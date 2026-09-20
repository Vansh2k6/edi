import { signedEnvelopeSchema, verifyEnvelope, type VerificationFailure } from '@pv/envelope';

/**
 * Device authentication (ARCHITECTURE.md boundary 2, `T010`).
 *
 * The extension signs every request with a device-bound key. This module is the
 * core's half of that contract: resolve the public key for a key id, verify the
 * envelope, and hand back the payload the signature actually covered.
 *
 * Fail closed in every direction:
 * - an unregistered key id is refused rather than trusted on first use,
 * - a key registered to another user is refused even with a valid signature,
 * - an expired or reused nonce is refused,
 * - a device-bound session that presents no signature is refused.
 *
 * The payload travels inside the envelope (`{ signed: { ... } }`) rather than
 * beside it. A header-duplicated body would be capped by the server's header size
 * limit and would leave a second copy of the payload for the signature not to
 * cover, so the signed value is the only value the route ever sees.
 */

export interface RegisteredDeviceKey {
  device_key_id: string;
  public_key: string;
  user_id: string;
}

export type DeviceKeyRegistration = { ok: true } | { ok: false; reason: 'key_id_conflict' };

export interface DeviceKeyRegistry {
  lookup(deviceKeyId: string): Promise<RegisteredDeviceKey | null>;
  /**
   * Register a key id. A key id that already exists under a different public key
   * or a different user is refused: accepting it would let one user take over
   * another's device identity.
   */
  register(key: RegisteredDeviceKey): Promise<DeviceKeyRegistration>;
}

/**
 * In-memory registry for development and tests.
 *
 * It starts empty on purpose: an unknown device is refused rather than trusted on
 * first use, and production needs a durable registry rather than this one.
 */
export class MemoryDeviceKeyRegistry implements DeviceKeyRegistry {
  readonly #keys = new Map<string, RegisteredDeviceKey>();

  register(key: RegisteredDeviceKey): Promise<DeviceKeyRegistration> {
    const existing = this.#keys.get(key.device_key_id);
    if (existing !== undefined && (existing.public_key !== key.public_key || existing.user_id !== key.user_id)) {
      return Promise.resolve({ ok: false, reason: 'key_id_conflict' });
    }
    this.#keys.set(key.device_key_id, key);
    return Promise.resolve({ ok: true });
  }

  lookup(deviceKeyId: string): Promise<RegisteredDeviceKey | null> {
    return Promise.resolve(this.#keys.get(deviceKeyId) ?? null);
  }
}

export interface NonceStore {
  has(nonce: string): Promise<boolean>;
  add(nonce: string): Promise<void>;
  /**
   * Atomically claim a nonce for single use.
   *
   * A check-then-add spread across two calls straddles the signature
   * verification await, so two concurrent requests carrying the same nonce can
   * both pass the check and both be accepted. `reserve` returns whether the
   * caller is the sole claimant in one step; on verification failure the claim
   * is given back with `release`, so garbage still cannot burn a nonce.
   */
  reserve(nonce: string): Promise<boolean>;
  /** Give back a claim made by `reserve` (verification failed). */
  release(nonce: string): Promise<void>;
}

/**
 * In-process nonce store.
 *
 * Bounded by count and by the replay window, so a chatty client cannot grow it
 * without limit. A multi-instance deployment swaps in Redis behind the same
 * interface; the replay guarantee then holds across instances instead of per
 * process, which is a deployment requirement rather than an optional upgrade.
 */
export class MemoryNonceStore implements NonceStore {
  readonly #entries = new Map<string, number>();
  readonly #windowMs: number;
  readonly #limit: number;

  constructor(options: { windowMs: number; limit?: number }) {
    this.#windowMs = options.windowMs;
    this.#limit = options.limit ?? 10_000;
  }

  async has(nonce: string): Promise<boolean> {
    const seenAt = this.#entries.get(nonce);
    if (seenAt === undefined) return false;
    if (Date.now() - seenAt > this.#windowMs) {
      this.#entries.delete(nonce);
      return false;
    }
    return true;
  }

  async add(nonce: string): Promise<void> {
    this.#entries.set(nonce, Date.now());
    this.#evict();
  }

  async reserve(nonce: string): Promise<boolean> {
    const now = Date.now();
    const seenAt = this.#entries.get(nonce);
    if (seenAt !== undefined && now - seenAt <= this.#windowMs) return false;
    // An expired entry, like an absent one, is claimable; the fresh claim also
    // refreshes its timestamp.
    this.#entries.set(nonce, now);
    this.#evict();
    return true;
  }

  async release(nonce: string): Promise<void> {
    this.#entries.delete(nonce);
  }

  #evict(): void {
    if (this.#entries.size <= this.#limit) return;
    const cutoff = Date.now() - this.#windowMs;
    for (const [key, seenAt] of this.#entries) {
      if (seenAt < cutoff) this.#entries.delete(key);
    }
    // Still full of fresh entries: drop the oldest rather than grow unbounded.
    while (this.#entries.size > this.#limit) {
      const oldest = this.#entries.keys().next();
      if (oldest.done === true) break;
      this.#entries.delete(oldest.value);
    }
  }
}

export interface DeviceRequestContext {
  registry: DeviceKeyRegistry;
  nonces: NonceStore;
  windowMs?: number;
  now?: Date;
}

export type DeviceAuthFailure = VerificationFailure | 'signature_required' | 'device_key_mismatch';

export type DeviceAuthResult =
  | { ok: true; device_key_id: string; user_id: string; payload: unknown }
  | { ok: false; reason: DeviceAuthFailure };

/** True when a body carries a signed envelope rather than a bare payload. */
export function isSignedRequest(body: unknown): boolean {
  return typeof body === 'object' && body !== null && 'signed' in body;
}

/**
 * Verify a signed request body.
 *
 * `sessionUserId` binds the signature to the authenticated session: a valid
 * signature from a key registered to another user is still refused.
 */
export async function authenticateDeviceRequest(
  body: unknown,
  sessionUserId: string,
  context: DeviceRequestContext,
): Promise<DeviceAuthResult> {
  const envelope = (body as { signed?: unknown }).signed;
  const parsed = signedEnvelopeSchema.safeParse(envelope);
  if (!parsed.success) return { ok: false, reason: 'malformed_envelope' };

  const registered = await context.registry.lookup(parsed.data.device_key_id);
  if (registered === null) return { ok: false, reason: 'unknown_device_key' };
  if (registered.user_id !== sessionUserId) return { ok: false, reason: 'device_key_mismatch' };

  // The claim is atomic: two concurrent requests with the same nonce cannot
  // both get past this line, which closes the verify-window replay race.
  if (!(await context.nonces.reserve(parsed.data.nonce))) return { ok: false, reason: 'replayed_nonce' };

  const verified = await verifyEnvelope(parsed.data, registered.public_key, {
    seenNonces: new Set<string>(),
    ...(context.now === undefined ? {} : { now: context.now }),
    ...(context.windowMs === undefined ? {} : { windowMs: context.windowMs }),
  });
  if (!verified.ok) {
    // Verification failed, so the nonce was never validly spent: give the
    // claim back rather than letting garbage burn it.
    await context.nonces.release(parsed.data.nonce);
    return { ok: false, reason: verified.reason };
  }

  // The nonce stays claimed for the whole replay window.

  return {
    ok: true,
    device_key_id: parsed.data.device_key_id,
    user_id: registered.user_id,
    payload: parsed.data.body,
  };
}
