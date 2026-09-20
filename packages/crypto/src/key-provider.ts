import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import {
  CryptoError,
  DEK_LENGTH,
  assertValidDek,
  fromBase64,
  toBase64,
} from './blob.js';

/**
 * Key management boundary (T006).
 *
 * The KEK never leaves the provider: callers only ever hand in a plaintext DEK
 * and receive wrapped material, or hand in wrapped material and receive the DEK.
 * No provider method returns the KEK, and none of them log.
 */

export interface WrappedDek {
  key_ref: string;
  kek_ref: string;
  algorithm: 'AES-256-GCM';
  /** base64 of [12 byte nonce][ciphertext || 16 byte tag] */
  wrapped: string;
}

export interface KeyProvider {
  readonly name: 'dev-shim' | 'kms';
  generateDek(): Promise<Uint8Array>;
  wrapDek(dek: Uint8Array, keyRef: string): Promise<WrappedDek>;
  unwrapDek(wrapped: WrappedDek): Promise<Uint8Array>;
}

/** Encode and decode the wrapped form: [nonce][ciphertext || tag]. */
function packWrapped(nonce: Uint8Array, ciphertext: Uint8Array): string {
  const out = new Uint8Array(nonce.length + ciphertext.length);
  out.set(nonce, 0);
  out.set(ciphertext, nonce.length);
  return toBase64(out);
}

function unpackWrapped(value: string): { nonce: Uint8Array; ciphertext: Uint8Array } {
  const raw = fromBase64(value);
  if (raw.length < 12 + 16) {
    throw new CryptoError('invalid_blob', 'wrapped key material is truncated');
  }
  return { nonce: raw.slice(0, 12), ciphertext: raw.slice(12) };
}

export interface DevShimOptions {
  /** Path outside the application tree, gitignored (infra/kms-dev). */
  kekFilePath: string;
  kekRef: string;
  nodeEnv?: string;
}

/**
 * Development-only KEK held in a local file.
 *
 * Refuses to operate in production so this cannot silently become the real key
 * management story (see D-024 and the risk table in the implementation plan).
 */
export class DevShimKeyProvider implements KeyProvider {
  readonly name = 'dev-shim' as const;
  readonly #kekFilePath: string;
  readonly #kekRef: string;
  readonly #nodeEnv: string;

  constructor(options: DevShimOptions) {
    this.#kekFilePath = options.kekFilePath;
    this.#kekRef = options.kekRef;
    this.#nodeEnv = options.nodeEnv ?? process.env.NODE_ENV ?? 'development';
  }

  #kek(): Uint8Array {
    if (this.#nodeEnv === 'production') {
      throw new CryptoError(
        'key_unavailable',
        'the development key shim refuses to run in production; configure a real key provider',
      );
    }
    let raw: string;
    try {
      raw = readFileSync(this.#kekFilePath, 'utf8');
    } catch {
      const generated = toBase64(randomBytes(DEK_LENGTH));
      mkdirSync(dirname(this.#kekFilePath), { recursive: true });
      writeFileSync(this.#kekFilePath, `${generated}\n`, { mode: 0o600 });
      raw = generated;
    }
    const kek = fromBase64(raw.trim());
    if (kek.length !== DEK_LENGTH) {
      throw new CryptoError('invalid_key', 'the development KEK file does not contain a 256-bit key');
    }
    return kek;
  }

  async generateDek(): Promise<Uint8Array> {
    return randomBytes(DEK_LENGTH);
  }

  async wrapDek(dek: Uint8Array, keyRef: string): Promise<WrappedDek> {
    assertValidDek(dek);
    const kek = this.#kek();
    const nonce = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', kek, nonce);
    cipher.setAAD(new TextEncoder().encode(`pv-dek|${keyRef}|${this.#kekRef}`));
    const ciphertext = Buffer.concat([cipher.update(dek), cipher.final(), cipher.getAuthTag()]);
    return {
      key_ref: keyRef,
      kek_ref: this.#kekRef,
      algorithm: 'AES-256-GCM',
      wrapped: packWrapped(new Uint8Array(nonce), new Uint8Array(ciphertext)),
    };
  }

  async unwrapDek(wrapped: WrappedDek): Promise<Uint8Array> {
    if (wrapped.algorithm !== 'AES-256-GCM') {
      throw new CryptoError('invalid_key', `unsupported key algorithm ${wrapped.algorithm}`);
    }
    const kek = this.#kek();
    const { nonce, ciphertext } = unpackWrapped(wrapped.wrapped);
    const tag = ciphertext.slice(ciphertext.length - 16);
    const body = ciphertext.slice(0, ciphertext.length - 16);
    const decipher = createDecipheriv('aes-256-gcm', kek, nonce);
    decipher.setAAD(new TextEncoder().encode(`pv-dek|${wrapped.key_ref}|${wrapped.kek_ref}`));
    decipher.setAuthTag(tag);
    try {
      const dek = new Uint8Array(Buffer.concat([decipher.update(body), decipher.final()]));
      assertValidDek(dek);
      return dek;
    } catch {
      throw new CryptoError(
        'key_unavailable',
        'the wrapped data key could not be unwrapped with this key-encryption key',
      );
    }
  }
}

/**
 * Placeholder for the real provider (cloud KMS or HSM). It refuses rather than
 * pretending, so an incomplete deployment fails closed and visibly.
 */
export class KmsKeyProvider implements KeyProvider {
  readonly name = 'kms' as const;

  async generateDek(): Promise<Uint8Array> {
    throw new CryptoError('key_unavailable', 'the KMS key provider is not implemented in this phase');
  }

  async wrapDek(_dek: Uint8Array, _keyRef: string): Promise<WrappedDek> {
    throw new CryptoError('key_unavailable', 'the KMS key provider is not implemented in this phase');
  }

  async unwrapDek(_wrapped: WrappedDek): Promise<Uint8Array> {
    throw new CryptoError('key_unavailable', 'the KMS key provider is not implemented in this phase');
  }
}

export function createKeyProvider(options: {
  provider: 'dev-shim' | 'kms';
  kekRef: string;
  nodeEnv?: string;
  devKekFilePath: string;
}): KeyProvider {
  return options.provider === 'kms'
    ? new KmsKeyProvider()
    : new DevShimKeyProvider({
        kekFilePath: options.devKekFilePath,
        kekRef: options.kekRef,
        ...(options.nodeEnv === undefined ? {} : { nodeEnv: options.nodeEnv }),
      });
}
