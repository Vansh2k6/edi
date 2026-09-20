import {
  REPLAY_WINDOW_MS,
  SIGNATURE_ALGORITHM,
  canonicalPayload,
  signedEnvelopeSchema,
  signedRequestSchema,
  type SignedEnvelope,
  type VerificationFailure,
  type VerificationResult,
} from '@pv/schemas';

/**
 * Device-bound request signing (ARCHITECTURE.md boundary 2).
 *
 * One implementation for both sides: the extension signs with a non-extractable
 * key pair generated in WebCrypto, and the core verifies with the same code, so a
 * change to the canonical encoding cannot desynchronise the two.
 *
 * Only WebCrypto is used, never a `node:` import, because this runs unchanged in
 * a browser worker and in Node (DEV-01).
 */

export { REPLAY_WINDOW_MS, SIGNATURE_ALGORITHM, signedEnvelopeSchema, signedRequestSchema };
export type { SignedEnvelope, VerificationFailure, VerificationResult };

/**
 * The WebCrypto types are derived from the runtime's own declarations rather than
 * named globals, because this package has to typecheck against the browser lib in
 * the extension and the Node types in the core without pulling in either one.
 */
type Subtle = typeof globalThis.crypto.subtle;
type GeneratedKey = Awaited<ReturnType<Subtle['generateKey']>>;
type CryptoKeyLike = Extract<GeneratedKey, { readonly type: string }>;
type CryptoKeyPairLike = Extract<GeneratedKey, { readonly privateKey: unknown }>;

function subtle(): Subtle {
  if (globalThis.crypto?.subtle === undefined) {
    throw new Error('WebCrypto is unavailable in this runtime');
  }
  return globalThis.crypto.subtle;
}

export function toBase64Url(bytes: ArrayBuffer | Uint8Array): string {
  const view = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let binary = '';
  for (const byte of view) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function fromBase64Url(value: string): Uint8Array {
  const padded = value.replace(/-/g, '+').replace(/_/g, '/');
  const binary = atob(padded + '='.repeat((4 - (padded.length % 4)) % 4));
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

/** WebCrypto wants `BufferSource`; the codec returns a typed array. */
function bytesOf(value: string): ArrayBuffer {
  return fromBase64Url(value) as unknown as ArrayBuffer;
}

export interface DeviceKeyMaterial {
  keyId: string;
  pair: CryptoKeyPairLike;
  publicKeyBase64: string;
}

/**
 * Generate the non-extractable device key pair.
 *
 * The private key is created non-extractable and never leaves the client: it
 * cannot be serialized by an attacker who reads the client's storage, only
 * used in place for signing. The public key stays extractable so it can be
 * registered with the core. The private key therefore must be persisted in a
 * structured-clone store (IndexedDB), never in a JSON one.
 */
export async function createDeviceKeyPair(): Promise<DeviceKeyMaterial> {
  const pair = (await subtle().generateKey({ name: SIGNATURE_ALGORITHM }, false, [
    'sign',
    'verify',
  ])) as CryptoKeyPairLike;
  const publicKey = await subtle().exportKey('raw', pair.publicKey);
  return { keyId: toBase64Url(publicKey).slice(0, 32), pair, publicKeyBase64: toBase64Url(publicKey) };
}

export async function signRequest(
  body: unknown,
  device: { keyId: string; pair: CryptoKeyPairLike },
  options: { now?: Date; nonce?: string } = {},
): Promise<SignedEnvelope> {
  const unsigned = {
    device_key_id: device.keyId,
    nonce: options.nonce ?? crypto.randomUUID(),
    timestamp: (options.now ?? new Date()).toISOString(),
    body,
  };
  const signature = await subtle().sign(SIGNATURE_ALGORITHM, device.pair.privateKey, canonicalPayload(unsigned));
  return { ...unsigned, algorithm: SIGNATURE_ALGORITHM, signature: toBase64Url(signature) };
}

export interface VerifyOptions {
  now?: Date;
  windowMs?: number;
  /** Nonces already accepted. A replay is refused, not merely recorded. */
  seenNonces: Set<string>;
}

/**
 * Verify an envelope against a registered public key.
 *
 * Order matters: cheap checks first, and a nonce is recorded only after the
 * signature is known good, so an attacker cannot burn a nonce by replaying
 * garbage. Every failure is a named reason: the caller must never have to guess
 * whether a rejection was a signature problem or a clock problem.
 */
export async function verifyEnvelope(
  envelope: unknown,
  publicKeyBase64: string,
  options: VerifyOptions,
): Promise<VerificationResult> {
  const parsed = signedEnvelopeSchema.safeParse(envelope);
  if (!parsed.success) return { ok: false, reason: 'malformed_envelope' };
  const candidate = parsed.data;

  const now = options.now ?? new Date();
  const windowMs = options.windowMs ?? REPLAY_WINDOW_MS;
  const timestamp = Date.parse(candidate.timestamp);
  if (Number.isNaN(timestamp) || Math.abs(now.getTime() - timestamp) > windowMs) {
    return { ok: false, reason: 'stale_timestamp' };
  }

  if (options.seenNonces.has(candidate.nonce)) {
    return { ok: false, reason: 'replayed_nonce' };
  }

  let publicKey: CryptoKeyLike;
  try {
    publicKey = await subtle().importKey('raw', bytesOf(publicKeyBase64), { name: SIGNATURE_ALGORITHM }, false, [
      'verify',
    ]);
  } catch {
    return { ok: false, reason: 'unknown_device_key' };
  }

  const valid = await subtle().verify(
    SIGNATURE_ALGORITHM,
    publicKey,
    bytesOf(candidate.signature),
    canonicalPayload({
      device_key_id: candidate.device_key_id,
      nonce: candidate.nonce,
      timestamp: candidate.timestamp,
      body: candidate.body,
    }),
  );
  if (!valid) return { ok: false, reason: 'bad_signature' };

  options.seenNonces.add(candidate.nonce);
  return { ok: true };
}
