/**
 * Consent state (W8.5).
 *
 * One store backs the dashboard's consent screen and the gateway's
 * disclosure-time re-check, so the two can never disagree: the API writes
 * here and the gateway reads here at release time. A consent is per owner
 * and per data category - the granularity every disclosure is bounded by.
 */

export interface ConsentRecord {
  user_id: string;
  data_category_id: string;
  status: 'Active' | 'Revoked';
  /** The consent record id carried into audit events that relied on this consent. */
  consent_id: string | null;
  updated_at: string;
}

export interface ConsentStore {
  listConsents(userId: string): Promise<ConsentRecord[]>;
  getConsent(userId: string, categoryId: string): Promise<ConsentRecord | null>;
  upsertConsent(record: ConsentRecord): Promise<void>;
}

export class MemoryConsentStore implements ConsentStore {
  readonly #rows = new Map<string, ConsentRecord>();

  #key(userId: string, categoryId: string): string {
    return `${userId}:${categoryId}`;
  }

  async listConsents(userId: string): Promise<ConsentRecord[]> {
    return [...this.#rows.values()].filter((row) => row.user_id === userId);
  }

  async getConsent(userId: string, categoryId: string): Promise<ConsentRecord | null> {
    return this.#rows.get(this.#key(userId, categoryId)) ?? null;
  }

  async upsertConsent(record: ConsentRecord): Promise<void> {
    this.#rows.set(this.#key(record.user_id, record.data_category_id), record);
  }
}
