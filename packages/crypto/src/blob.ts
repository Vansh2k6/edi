/**
 * Blob format v1 (D-024):
 *
 *   [1 byte version][12 byte nonce][ciphertext || 16 byte GCM tag]
 *
 * The same bytes are produced by the Node implementation and by WebCrypto, so a
 * blob written by the extension decrypts in the core and vice versa.
 *
 * Everything is bound to its entry through additional authenticated data built
 * from the data id, owner and category. Moving a blob to another entry, or
 * renaming its category, therefore fails authentication rather than silently
 * decrypting under the wrong identity.
 */

export const BLOB_VERSION = 1;
export const NONCE_LENGTH = 12;
export const TAG_LENGTH = 16;
export const DEK_LENGTH = 32;
export const HEADER_LENGTH = 1 + NONCE_LENGTH;
export const MIN_BLOB_LENGTH = HEADER_LENGTH + TAG_LENGTH;

export type CryptoErrorCode =
  | 'invalid_blob'
  | 'unsupported_version'
  | 'auth_failed'
  | 'key_unavailable'
  | 'invalid_key'
  | 'unsupported_runtime';

export class CryptoError extends Error {
  readonly code: CryptoErrorCode;

  constructor(code: CryptoErrorCode, message: string) {
    super(message);
    this.name = 'CryptoError';
    this.code = code;
  }
}

/** Identity a blob is bound to. Values come from verified state, never a page. */
export interface EntryBinding {
  data_id: string;
  user_id: string;
  data_category_id: string;
}

const AAD_PREFIX = 'pv-blob-v1';

export function buildAad(binding: EntryBinding): Uint8Array {
  const canonical = [AAD_PREFIX, binding.data_id, binding.user_id, binding.data_category_id].join('\u001f');
  return new TextEncoder().encode(canonical);
}

export function encodeBlob(nonce: Uint8Array, ciphertext: Uint8Array, version = BLOB_VERSION): Uint8Array {
  if (nonce.length !== NONCE_LENGTH) {
    throw new CryptoError('invalid_blob', `nonce must be ${NONCE_LENGTH} bytes`);
  }
  if (ciphertext.length < TAG_LENGTH) {
    throw new CryptoError('invalid_blob', 'ciphertext is shorter than the authentication tag');
  }
  const out = new Uint8Array(HEADER_LENGTH + ciphertext.length);
  out[0] = version;
  out.set(nonce, 1);
  out.set(ciphertext, HEADER_LENGTH);
  return out;
}

export interface DecodedBlob {
  version: number;
  nonce: Uint8Array;
  ciphertext: Uint8Array;
}

export function decodeBlob(blob: Uint8Array): DecodedBlob {
  if (blob.length < MIN_BLOB_LENGTH) {
    throw new CryptoError('invalid_blob', 'blob is truncated or empty');
  }
  const version = blob[0];
  if (version !== BLOB_VERSION) {
    throw new CryptoError('unsupported_version', `unsupported blob version ${String(version)}`);
  }
  return {
    version,
    nonce: blob.slice(1, HEADER_LENGTH),
    ciphertext: blob.slice(HEADER_LENGTH),
  };
}

export function generateDek(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(DEK_LENGTH));
}

export function assertValidDek(dek: Uint8Array): void {
  if (dek.length !== DEK_LENGTH) {
    throw new CryptoError('invalid_key', `data-encryption keys must be ${DEK_LENGTH} bytes`);
  }
}

export function toBase64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64');
}

export function fromBase64(value: string): Uint8Array {
  return new Uint8Array(Buffer.from(value, 'base64'));
}
