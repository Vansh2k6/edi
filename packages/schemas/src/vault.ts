import { z } from 'zod';

/** Data categories are extensible configuration, not a fixed enum (D-004). */
export const sensitivitySchema = z.enum(['Low', 'Medium', 'High', 'Critical']);
export type SensitivityLevel = z.infer<typeof sensitivitySchema>;

export const dataCategorySchema = z.strictObject({
  data_category_id: z.string().min(1).max(36),
  category_name: z.string().min(1).max(100),
  sensitivity_level: sensitivitySchema,
});
export type DataCategory = z.infer<typeof dataCategorySchema>;

export const dataCategoryRegistrySchema = z.array(dataCategorySchema).min(1).max(120);

export const dataStatusSchema = z.enum(['Active', 'Archived', 'Deleted']);
export const storageTierSchema = z.enum(['local', 'server']);
export type StorageTier = z.infer<typeof storageTierSchema>;

/** Roughly 1.5 MiB of plaintext, base64-expanded. */
export const MAX_CIPHERTEXT_BASE64 = 2_100_000;
export const MAX_METADATA_KEYS = 32;

const digestSchema = z.string().regex(/^[0-9a-f]{64}$/, 'expected a lowercase hex sha256 digest');

/**
 * Vault create payload.
 *
 * The plaintext never reaches the core, and neither does a key: for the `local`
 * tier the ciphertext stays in the client and only a digest plus the wrapped DEK
 * are stored; for the `server` tier the ciphertext blob is sent (D-022).
 */
export const vaultCreateRequestSchema = z
  .strictObject({
    data_category_id: z.string().min(1).max(36),
    storage_tier: storageTierSchema,
    ciphertext: z.string().min(1).max(MAX_CIPHERTEXT_BASE64).nullable(),
    integrity_digest: digestSchema,
    wrapped_dek: z.string().min(1).max(4096),
    /** Optional client-declared location label; never a filesystem path on the server. */
    storage_location: z.string().max(150).nullable().default(null),
    client_metadata: z.record(z.string().min(1).max(64), z.string().max(256)).default({}),
  })
  .superRefine((value, ctx) => {
    if (Object.keys(value.client_metadata).length > MAX_METADATA_KEYS) {
      ctx.addIssue({ code: 'custom', path: ['client_metadata'], message: 'too many metadata keys' });
    }
    if (value.storage_tier === 'server' && value.ciphertext === null) {
      ctx.addIssue({
        code: 'custom',
        path: ['ciphertext'],
        message: 'server-tier entries must carry ciphertext',
      });
    }
    if (value.storage_tier === 'local' && value.ciphertext !== null) {
      ctx.addIssue({
        code: 'custom',
        path: ['ciphertext'],
        message: 'local-tier entries must not send ciphertext to the core',
      });
    }
  });
export type VaultCreateRequest = z.infer<typeof vaultCreateRequestSchema>;

/** Metadata projection returned to clients. Ciphertext is never included. */
export const vaultEntrySchema = z.strictObject({
  data_id: z.uuid(),
  data_category_id: z.string().min(1).max(36),
  storage_tier: storageTierSchema,
  storage_location: z.string().max(150).nullable(),
  data_status: dataStatusSchema,
  integrity_digest: digestSchema,
  created_at: z.iso.datetime(),
  updated_at: z.iso.datetime(),
});
export type VaultEntry = z.infer<typeof vaultEntrySchema>;

export const vaultEntryListSchema = z.array(vaultEntrySchema).max(500);

export const keyRecordSchema = z.strictObject({
  key_id: z.uuid(),
  user_id: z.uuid(),
  algorithm: z.literal('AES-256-GCM'),
  key_status: z.enum(['Active', 'Rotated', 'Revoked']),
  created_at: z.iso.datetime(),
  rotated_at: z.iso.datetime().nullable(),
});
export type KeyRecord = z.infer<typeof keyRecordSchema>;
