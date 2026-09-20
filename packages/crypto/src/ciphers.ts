import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import {
  BLOB_VERSION,
  CryptoError,
  NONCE_LENGTH,
  assertValidDek,
  buildAad,
  decodeBlob,
  encodeBlob,
  type EntryBinding,
} from './blob.js';

/**
 * A cipher seals and opens blobs. Both implementations below are interchangeable
 * and byte-compatible; the extension uses WebCrypto, the core uses node:crypto.
 */
export interface Cipher {
  readonly runtime: 'node' | 'webcrypto';
  seal(dek: Uint8Array, plaintext: Uint8Array, aad: Uint8Array): Promise<Uint8Array>;
  open(dek: Uint8Array, blob: Uint8Array, aad: Uint8Array): Promise<Uint8Array>;
}

function asUint8(bytes: Uint8Array | Buffer): Uint8Array {
  return new Uint8Array(bytes.buffer, bytes.byteOffset, bytes.byteLength);
}

export const nodeCipher: Cipher = {
  runtime: 'node',

  async seal(dek, plaintext, aad) {
    assertValidDek(dek);
    const nonce = randomBytes(NONCE_LENGTH);
    const cipher = createCipheriv('aes-256-gcm', dek, nonce);
    cipher.setAAD(aad);
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]);
    return encodeBlob(asUint8(nonce), asUint8(ciphertext));
  },

  async open(dek, blob, aad) {
    assertValidDek(dek);
    const { nonce, ciphertext } = decodeBlob(blob);
    const tag = ciphertext.slice(ciphertext.length - 16);
    const body = ciphertext.slice(0, ciphertext.length - 16);
    const decipher = createDecipheriv('aes-256-gcm', dek, nonce);
    decipher.setAAD(aad);
    decipher.setAuthTag(tag);
    try {
      return asUint8(Buffer.concat([decipher.update(body), decipher.final()]));
    } catch {
      // Never surface partial plaintext or the underlying error detail.
      throw new CryptoError('auth_failed', 'ciphertext failed authentication for this key and binding');
    }
  },
};

/*
 * Minimal structural typing for WebCrypto.
 *
 * This package is compiled without the DOM lib (the core must not see DOM
 * globals) and without dragging in node:crypto's runtime types for code that
 * also runs in the browser, so only the three calls actually used are typed.
 */
type Bytes = ArrayBufferView | ArrayBuffer;
type WebCryptoKey = object;

interface MinimalSubtleCrypto {
  importKey(
    format: 'raw',
    keyData: Bytes,
    algorithm: { name: 'AES-GCM' },
    extractable: boolean,
    keyUsages: string[],
  ): Promise<WebCryptoKey>;
  encrypt(
    algorithm: { name: 'AES-GCM'; iv: Bytes; additionalData?: Bytes; tagLength?: number },
    key: WebCryptoKey,
    data: Bytes,
  ): Promise<ArrayBuffer>;
  decrypt(
    algorithm: { name: 'AES-GCM'; iv: Bytes; additionalData?: Bytes; tagLength?: number },
    key: WebCryptoKey,
    data: Bytes,
  ): Promise<ArrayBuffer>;
}

function subtle(): MinimalSubtleCrypto {
  const cryptoImpl = globalThis.crypto as { subtle?: unknown } | undefined;
  if (!cryptoImpl?.subtle) {
    throw new CryptoError('unsupported_runtime', 'WebCrypto is not available in this runtime');
  }
  return cryptoImpl.subtle as MinimalSubtleCrypto;
}

async function importKey(dek: Uint8Array, usage: 'encrypt' | 'decrypt'): Promise<WebCryptoKey> {
  assertValidDek(dek);
  const keyData: Bytes = dek as unknown as Bytes;
  return subtle().importKey('raw', keyData, { name: 'AES-GCM' }, false, [usage]);
}

export const webCryptoCipher: Cipher = {
  runtime: 'webcrypto',

  async seal(dek, plaintext, aad) {
    const key = await importKey(dek, 'encrypt');
    const nonce = crypto.getRandomValues(new Uint8Array(NONCE_LENGTH));
    const ciphertext = await subtle().encrypt(
      { name: 'AES-GCM', iv: nonce as unknown as Bytes, additionalData: aad as unknown as Bytes, tagLength: 128 },
      key,
      plaintext as unknown as Bytes,
    );
    return encodeBlob(nonce, new Uint8Array(ciphertext), BLOB_VERSION);
  },

  async open(dek, blob, aad) {
    const key = await importKey(dek, 'decrypt');
    const { nonce, ciphertext } = decodeBlob(blob);
    try {
      const plaintext = await subtle().decrypt(
        { name: 'AES-GCM', iv: nonce as unknown as Bytes, additionalData: aad as unknown as Bytes, tagLength: 128 },
        key,
        ciphertext as unknown as Bytes,
      );
      return new Uint8Array(plaintext);
    } catch {
      throw new CryptoError('auth_failed', 'ciphertext failed authentication for this key and binding');
    }
  },
};

export async function sealString(cipher: Cipher, binding: EntryBinding, dek: Uint8Array, plaintext: string): Promise<Uint8Array> {
  return cipher.seal(dek, new TextEncoder().encode(plaintext), buildAad(binding));
}

export async function openString(cipher: Cipher, binding: EntryBinding, dek: Uint8Array, blob: Uint8Array): Promise<string> {
  const bytes = await cipher.open(dek, blob, buildAad(binding));
  return new TextDecoder().decode(bytes);
}
