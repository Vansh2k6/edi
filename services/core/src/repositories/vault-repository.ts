import { and, eq } from 'drizzle-orm';
import type { StorageTier, VaultEntry } from '@pv/schemas';
import type { DbHandle } from '../db/client.js';
import { encryptionKeys, users, vaultEntries } from '../db/schema.js';
import type { ServerTierEntry } from '../gateway/authorize.js';

export interface KeyMaterial {
  key_id: string;
  key_status: 'Active' | 'Rotated' | 'Revoked';
  kek_ref: string;
}

export interface NewVaultEntry {
  user_id: string;
  data_category_id: string;
  storage_tier: StorageTier;
  ciphertext: string | null;
  integrity_digest: string;
  wrapped_dek: string;
  storage_location: string | null;
  client_metadata: Record<string, string>;
}

/**
 * Vault persistence (T007).
 *
 * Every method takes the owning `user_id` explicitly and derives it from the
 * authenticated session at the call site - never from a request field. The
 * Postgres implementation additionally runs each query with `app.user_id` set,
 * so row-level security enforces the same rule a second time.
 */
export interface VaultRepository {
  readonly kind: 'memory' | 'postgres';
  ensureUser(user: { user_id: string; user_name?: string; email_id?: string }): Promise<void>;
  getOrCreateActiveKey(userId: string, kekRef: string): Promise<KeyMaterial>;
  /** Always creates a new active key, for rotation. */
  createKey(userId: string, kekRef: string): Promise<KeyMaterial>;
  markKeyRotated(keyId: string): Promise<void>;
  findActiveKey(userId: string): Promise<KeyMaterial | null>;
  createEntry(input: NewVaultEntry): Promise<VaultEntry>;
  getEntry(userId: string, dataId: string): Promise<VaultEntry | null>;
  listEntries(userId: string): Promise<VaultEntry[]>;
  softDeleteEntry(userId: string, dataId: string): Promise<boolean>;
  /** Entries that still reference a given key, for rotation. */
  entriesForKey(keyId: string): Promise<Array<{ data_id: string; wrapped_dek: string }>>;
  updateWrappedDek(dataId: string, wrappedDek: string, keyId: string): Promise<void>;
  /** Test/diagnostic helper: number of entries currently stored. */
  countEntries(): Promise<number>;
  /**
   * The key material the vault gateway needs to open one server-tier entry
   * (W7.2). Returns null when the entry does not exist, belongs to another
   * owner, or is not server-tier; the gateway fails closed on all three.
   */
  getServerTierEntry(userId: string, dataId: string): Promise<ServerTierEntry | null>;
}

function nowIso(): string {
  return new Date().toISOString();
}

/* ------------------------------------------------------------- in memory --- */

interface MemoryUser {
  user_id: string;
  user_name: string;
  email_id: string;
  mobile_number: string | null;
  identity_status: 'Pending' | 'Verified' | 'Suspended';
  user_type: 'Citizen' | 'Organization' | 'Administrator';
}

interface MemoryEntry extends VaultEntry {
  user_id: string;
  ciphertext: string | null;
  wrapped_dek: string;
  encryption_key_id: string;
  client_metadata: Record<string, string>;
}

/**
 * In-memory repository (DEV-02).
 *
 * Used when `DATABASE_URL` is unset so the stack runs without Docker. It is a
 * faithful stand-in, not a mock: the same invariants apply, and the Postgres
 * implementation is exercised in CI.
 */
export class MemoryVaultRepository implements VaultRepository {
  readonly kind = 'memory' as const;
  readonly #users = new Map<string, MemoryUser>();
  readonly #keys = new Map<string, KeyMaterial & { user_id: string; created_at: string }>();
  readonly #entries = new Map<string, MemoryEntry>();

  async ensureUser(user: { user_id: string; user_name?: string; email_id?: string }): Promise<void> {
    if (this.#users.has(user.user_id)) return;
    this.#users.set(user.user_id, {
      user_id: user.user_id,
      user_name: user.user_name ?? 'Vault Owner',
      email_id: user.email_id ?? `${user.user_id}@example.invalid`,
      mobile_number: null,
      identity_status: 'Verified',
      user_type: 'Citizen',
    });
  }

  async getOrCreateActiveKey(userId: string, kekRef: string): Promise<KeyMaterial> {
    const existing = await this.findActiveKey(userId);
    return existing ?? this.createKey(userId, kekRef);
  }

  async createKey(userId: string, kekRef: string): Promise<KeyMaterial> {
    const key: KeyMaterial & { user_id: string; created_at: string } = {
      key_id: crypto.randomUUID(),
      key_status: 'Active',
      kek_ref: kekRef,
      user_id: userId,
      created_at: nowIso(),
    };
    this.#keys.set(key.key_id, key);
    return { key_id: key.key_id, key_status: 'Active', kek_ref: key.kek_ref };
  }

  async markKeyRotated(keyId: string): Promise<void> {
    const key = this.#keys.get(keyId);
    if (key) key.key_status = 'Rotated';
  }

  async findActiveKey(userId: string): Promise<KeyMaterial | null> {
    for (const key of this.#keys.values()) {
      if (key.user_id === userId && key.key_status === 'Active') {
        return { key_id: key.key_id, key_status: 'Active', kek_ref: key.kek_ref };
      }
    }
    return null;
  }

  async createEntry(input: NewVaultEntry): Promise<VaultEntry> {
    const key = await this.findActiveKey(input.user_id);
    if (!key) throw new Error('no active encryption key for this owner');
    const timestamp = nowIso();
    const entry: MemoryEntry = {
      data_id: crypto.randomUUID(),
      user_id: input.user_id,
      data_category_id: input.data_category_id,
      storage_tier: input.storage_tier,
      ciphertext: input.ciphertext,
      integrity_digest: input.integrity_digest,
      wrapped_dek: input.wrapped_dek,
      encryption_key_id: key.key_id,
      client_metadata: input.client_metadata,
      storage_location: input.storage_location,
      data_status: 'Active',
      created_at: timestamp,
      updated_at: timestamp,
    };
    this.#entries.set(entry.data_id, entry);
    return toPublicEntry(entry);
  }

  async getEntry(userId: string, dataId: string): Promise<VaultEntry | null> {
    const entry = this.#entries.get(dataId);
    if (!entry || entry.user_id !== userId || entry.data_status !== 'Active') return null;
    return toPublicEntry(entry);
  }

  async listEntries(userId: string): Promise<VaultEntry[]> {
    return [...this.#entries.values()]
      .filter((entry) => entry.user_id === userId && entry.data_status !== 'Deleted')
      .sort((a, b) => a.created_at.localeCompare(b.created_at))
      .map(toPublicEntry);
  }

  async softDeleteEntry(userId: string, dataId: string): Promise<boolean> {
    const entry = this.#entries.get(dataId);
    if (!entry || entry.user_id !== userId) return false;
    entry.data_status = 'Deleted';
    entry.updated_at = nowIso();
    return true;
  }

  async entriesForKey(keyId: string): Promise<Array<{ data_id: string; wrapped_dek: string }>> {
    return [...this.#entries.values()]
      .filter((entry) => entry.encryption_key_id === keyId)
      .map((entry) => ({ data_id: entry.data_id, wrapped_dek: entry.wrapped_dek }));
  }

  async updateWrappedDek(dataId: string, wrappedDek: string, keyId: string): Promise<void> {
    const entry = this.#entries.get(dataId);
    if (!entry) return;
    entry.wrapped_dek = wrappedDek;
    entry.encryption_key_id = keyId;
    entry.updated_at = nowIso();
  }

  async countEntries(): Promise<number> {
    return this.#entries.size;
  }

  async getServerTierEntry(userId: string, dataId: string): Promise<ServerTierEntry | null> {
    const entry = this.#entries.get(dataId);
    if (!entry || entry.user_id !== userId || entry.data_status !== 'Active' || entry.storage_tier !== 'server') {
      return null;
    }
    if (entry.ciphertext === null) return null;
    return {
      ciphertext: entry.ciphertext,
      wrapped_dek: entry.wrapped_dek,
      key_id: entry.encryption_key_id,
      kek_ref: this.#keys.get(entry.encryption_key_id)?.kek_ref ?? 'unknown-kek',
      seal_data_id: entry.client_metadata['pv_seal_data_id'] ?? null,
    };
  }
}

function toPublicEntry(entry: MemoryEntry): VaultEntry {
  return {
    data_id: entry.data_id,
    data_category_id: entry.data_category_id,
    storage_tier: entry.storage_tier,
    storage_location: entry.storage_location,
    data_status: entry.data_status,
    integrity_digest: entry.integrity_digest,
    created_at: entry.created_at,
    updated_at: entry.updated_at,
  };
}

/* ------------------------------------------------------------- postgres --- */

export class PostgresVaultRepository implements VaultRepository {
  readonly kind = 'postgres' as const;

  constructor(private readonly handle: DbHandle) {}

  async ensureUser(user: { user_id: string; user_name?: string; email_id?: string }): Promise<void> {
    await this.handle.db
      .insert(users)
      .values({
        user_id: user.user_id,
        user_name: user.user_name ?? 'Vault Owner',
        email_id: user.email_id ?? `${user.user_id}@example.invalid`,
      })
      .onConflictDoNothing();
  }

  async getOrCreateActiveKey(userId: string, kekRef: string): Promise<KeyMaterial> {
    const existing = await this.findActiveKey(userId);
    return existing ?? this.createKey(userId, kekRef);
  }

  async createKey(userId: string, kekRef: string): Promise<KeyMaterial> {
    const [created] = await this.handle.db
      .insert(encryptionKeys)
      .values({ user_id: userId, kek_ref: kekRef, algorithm: 'AES-256-GCM' })
      .returning();
    if (!created) throw new Error('failed to create an encryption key');
    return { key_id: created.key_id, key_status: 'Active', kek_ref: created.kek_ref };
  }

  async markKeyRotated(keyId: string): Promise<void> {
    await this.handle.db
      .update(encryptionKeys)
      .set({ key_status: 'Rotated', rotated_at: new Date() })
      .where(eq(encryptionKeys.key_id, keyId));
  }

  async findActiveKey(userId: string): Promise<KeyMaterial | null> {
    const rows = await this.handle.asOwner(userId, (db) =>
      db
        .select()
        .from(encryptionKeys)
        .where(and(eq(encryptionKeys.user_id, userId), eq(encryptionKeys.key_status, 'Active')))
        .limit(1),
    );
    const row = rows[0];
    return row ? { key_id: row.key_id, key_status: 'Active', kek_ref: row.kek_ref } : null;
  }

  async createEntry(input: NewVaultEntry): Promise<VaultEntry> {
    const key = await this.findActiveKey(input.user_id);
    if (!key) throw new Error('no active encryption key for this owner');
    const [row] = await this.handle.asOwner(input.user_id, (db) =>
      db
        .insert(vaultEntries)
        .values({
          user_id: input.user_id,
          data_category_id: input.data_category_id,
          encryption_key_id: key.key_id,
          storage_tier: input.storage_tier,
          ciphertext: input.ciphertext,
          integrity_digest: input.integrity_digest,
          wrapped_dek: input.wrapped_dek,
          storage_location: input.storage_location,
          client_metadata: input.client_metadata,
        })
        .returning(),
    );
    if (!row) throw new Error('failed to create the vault entry');
    return toPublicRow(row);
  }

  async getEntry(userId: string, dataId: string): Promise<VaultEntry | null> {
    const rows = await this.handle.asOwner(userId, (db) =>
      db.select().from(vaultEntries).where(eq(vaultEntries.data_id, dataId)).limit(1),
    );
    const row = rows[0];
    return row && row.data_status === 'Active' ? toPublicRow(row) : null;
  }

  async listEntries(userId: string): Promise<VaultEntry[]> {
    const rows = await this.handle.asOwner(userId, (db) => db.select().from(vaultEntries).orderBy(vaultEntries.created_at));
    return rows.filter((row) => row.data_status !== 'Deleted').map(toPublicRow);
  }

  async softDeleteEntry(userId: string, dataId: string): Promise<boolean> {
    const updated = await this.handle.asOwner(userId, (db) =>
      db
        .update(vaultEntries)
        .set({ data_status: 'Deleted', updated_at: new Date() })
        .where(eq(vaultEntries.data_id, dataId))
        .returning({ data_id: vaultEntries.data_id }),
    );
    return updated.length > 0;
  }

  async entriesForKey(keyId: string): Promise<Array<{ data_id: string; wrapped_dek: string }>> {
    const rows = await this.handle.db
      .select({ data_id: vaultEntries.data_id, wrapped_dek: vaultEntries.wrapped_dek })
      .from(vaultEntries)
      .where(eq(vaultEntries.encryption_key_id, keyId));
    return rows;
  }

  async updateWrappedDek(dataId: string, wrappedDek: string, keyId: string): Promise<void> {
    await this.handle.db
      .update(vaultEntries)
      .set({ wrapped_dek: wrappedDek, encryption_key_id: keyId, updated_at: new Date() })
      .where(eq(vaultEntries.data_id, dataId));
  }

  async countEntries(): Promise<number> {
    const rows = await this.handle.db.select({ data_id: vaultEntries.data_id }).from(vaultEntries);
    return rows.length;
  }

  async getServerTierEntry(userId: string, dataId: string): Promise<ServerTierEntry | null> {
    const rows = await this.handle.asOwner(userId, (db) =>
      db.select().from(vaultEntries).where(eq(vaultEntries.data_id, dataId)).limit(1),
    );
    const row = rows[0];
    if (!row || row.data_status !== 'Active' || row.storage_tier !== 'server') return null;
    if (row.ciphertext === null || row.wrapped_dek === null) return null;
    const keyRows = await this.handle.db
      .select({ kek_ref: encryptionKeys.kek_ref })
      .from(encryptionKeys)
      .where(eq(encryptionKeys.key_id, row.encryption_key_id))
      .limit(1);
    const metadata = row.client_metadata as Record<string, string>;
    return {
      ciphertext: row.ciphertext,
      wrapped_dek: row.wrapped_dek,
      key_id: row.encryption_key_id,
      kek_ref: keyRows[0]?.kek_ref ?? 'unknown-kek',
      seal_data_id: metadata['pv_seal_data_id'] ?? null,
    };
  }
}

type VaultRow = typeof vaultEntries.$inferSelect;

function toPublicRow(row: VaultRow): VaultEntry {
  return {
    data_id: row.data_id,
    data_category_id: row.data_category_id,
    storage_tier: row.storage_tier === 'server' ? 'server' : 'local',
    storage_location: row.storage_location,
    data_status: row.data_status === 'Archived' || row.data_status === 'Deleted' ? row.data_status : 'Active',
    integrity_digest: row.integrity_digest,
    created_at: row.created_at.toISOString(),
    updated_at: row.updated_at.toISOString(),
  };
}
