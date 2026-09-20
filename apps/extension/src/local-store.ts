/**
 * Local-tier storage (D-022, W2.6).
 *
 * Ciphertext for sensitive categories stays in this browser. Two states matter
 * and both are explicit: a stored value, or a stated reason why it is not
 * available. An empty result must never be indistinguishable from "the vault
 * entry exists but this device cannot read it".
 */

export interface StorageArea {
  get(keys: string[]): Promise<Record<string, unknown>>;
  set(items: Record<string, unknown>): Promise<void>;
  remove(keys: string[]): Promise<void>;
}

export type LocalReadResult =
  | { ok: true; ciphertext: string }
  | { ok: false; reason: 'not_stored' | 'storage_unavailable' | 'corrupt_entry' };

export type LocalWriteResult = { ok: true } | { ok: false; reason: 'quota_exceeded' | 'storage_unavailable' };

const PREFIX = 'pv:blob:';

function keyFor(dataId: string): string {
  return `${PREFIX}${dataId}`;
}

export class LocalVaultStore {
  constructor(private readonly area: StorageArea) {}

  async put(dataId: string, ciphertext: string): Promise<LocalWriteResult> {
    try {
      await this.area.set({ [keyFor(dataId)]: { ciphertext, stored_at: new Date().toISOString() } });
      return { ok: true };
    } catch (error) {
      const message = error instanceof Error ? error.message : '';
      return { ok: false, reason: /quota|QUOTA_BYTES/i.test(message) ? 'quota_exceeded' : 'storage_unavailable' };
    }
  }

  async get(dataId: string): Promise<LocalReadResult> {
    let raw: Record<string, unknown>;
    try {
      raw = await this.area.get([keyFor(dataId)]);
    } catch {
      return { ok: false, reason: 'storage_unavailable' };
    }
    const entry = raw[keyFor(dataId)];
    if (entry === undefined) return { ok: false, reason: 'not_stored' };
    if (typeof entry !== 'object' || entry === null || typeof (entry as { ciphertext?: unknown }).ciphertext !== 'string') {
      return { ok: false, reason: 'corrupt_entry' };
    }
    return { ok: true, ciphertext: (entry as { ciphertext: string }).ciphertext };
  }

  async remove(dataId: string): Promise<void> {
    try {
      await this.area.remove([keyFor(dataId)]);
    } catch {
      // Removal failure is not fatal here: retention re-checks later.
    }
  }

  async list(dataIds: readonly string[]): Promise<Record<string, LocalReadResult>> {
    const out: Record<string, LocalReadResult> = {};
    for (const dataId of dataIds) {
      out[dataId] = await this.get(dataId);
    }
    return out;
  }
}
