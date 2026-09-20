import type { KeyProvider } from '@pv/crypto';
import type { VaultRepository } from './repositories/vault-repository.js';

export interface RotationReport {
  old_key_id: string | null;
  new_key_id: string;
  rekeyed_entries: number;
  /** Entries whose wrapped key could not be moved; they stay on the old key. */
  failed_entries: string[];
}

/**
 * Rotate one owner's key (T006).
 *
 * The data-encryption key is unwrapped with the previous key reference and
 * re-wrapped under the new one; the ciphertext is never touched, because
 * rotating a key must not require rewriting every payload. The KEK never leaves
 * the provider, so this function never sees it either.
 */
export async function rotateUserKey(dependencies: {
  repository: VaultRepository;
  provider: KeyProvider;
  userId: string;
  kekRef: string;
}): Promise<RotationReport> {
  const { repository, provider, userId, kekRef } = dependencies;
  const previous = await repository.findActiveKey(userId);
  const created = await repository.createKey(userId, kekRef);

  const report: RotationReport = {
    old_key_id: previous?.key_id ?? null,
    new_key_id: created.key_id,
    rekeyed_entries: 0,
    failed_entries: [],
  };

  if (previous === null || previous.key_id === created.key_id) {
    // Nothing was ever wrapped under a previous key: the new key simply becomes
    // the active one.
    return report;
  }

  await repository.markKeyRotated(previous.key_id);

  for (const entry of await repository.entriesForKey(previous.key_id)) {
    try {
      const dek = await provider.unwrapDek({
        key_ref: previous.key_id,
        kek_ref: previous.kek_ref,
        algorithm: 'AES-256-GCM',
        wrapped: entry.wrapped_dek,
      });
      const rewrapped = await provider.wrapDek(dek, created.key_id);
      await repository.updateWrappedDek(entry.data_id, rewrapped.wrapped, created.key_id);
      report.rekeyed_entries += 1;
    } catch {
      // A key that cannot be moved stays where it is rather than failing the whole
      // rotation; the failure is reported instead of hidden.
      report.failed_entries.push(entry.data_id);
    }
  }

  return report;
}
