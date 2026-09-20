import { z } from 'zod';

/**
 * Signed request envelope (ARCHITECTURE.md boundary 2).
 *
 * Every request between the extension and the core is signed by a device-bound
 * key. The signature covers the canonical encoding below, never the raw JSON, so
 * that key ordering cannot change the meaning of a signed request.
 *
 * The contract lives here so the extension signs exactly what the core verifies
 * (D-023): there is one schema and one canonical encoding, not one per side.
 */

export const SIGNATURE_ALGORITHM = 'Ed25519';

/** How far a signed timestamp may be from the verifier's clock. */
export const REPLAY_WINDOW_MS = 60_000;

export const MAX_ENVELOPE_BODY_BYTES = 2_300_000;

export const signedEnvelopeSchema = z.strictObject({
  device_key_id: z.string().min(1).max(128),
  /** Single-use value; a repeat inside the window is a replay. */
  nonce: z.string().min(16).max(128),
  timestamp: z.iso.datetime(),
  algorithm: z.literal(SIGNATURE_ALGORITHM),
  /** base64url of the signature over the canonical encoding. */
  signature: z.string().min(1).max(1024),
  body: z.unknown(),
});
export type SignedEnvelope = z.infer<typeof signedEnvelopeSchema>;

export type VerificationFailure =
  | 'malformed_envelope'
  | 'unknown_device_key'
  | 'stale_timestamp'
  | 'replayed_nonce'
  | 'bad_signature';

export type VerificationResult = { ok: true } | { ok: false; reason: VerificationFailure };

/**
 * The bytes a signature covers.
 *
 * Fixed field order, newline separated, with the body serialised once. A verifier
 * that re-serialises the body differently would reject a valid signature, so both
 * sides call this function rather than rebuilding the string.
 */
export function canonicalPayload(envelope: {
  device_key_id: string;
  nonce: string;
  timestamp: string;
  body: unknown;
}): ArrayBuffer {
  const encoded = new TextEncoder().encode(
    [envelope.device_key_id, envelope.nonce, envelope.timestamp, JSON.stringify(envelope.body)].join('\n'),
  );
  // WebCrypto's parameter types are narrower than the inferred typed-array type.
  return encoded as unknown as ArrayBuffer;
}

/**
 * The wire shape of a signed request: `{ signed: <envelope> }`.
 *
 * The payload travels inside the envelope rather than beside it, so the value the
 * route acts on is the value the signature covered and the server's header size
 * limit cannot silently truncate a large body.
 */
export const signedRequestSchema = z.strictObject({ signed: signedEnvelopeSchema });
export type SignedRequest = z.infer<typeof signedRequestSchema>;
