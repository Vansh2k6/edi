import type { AuditEvent, AuditEventInput } from '@pv/schemas';
import { appendToChain, type ChainPosition } from '@pv/audit';

/**
 * Audit persistence (`T038`, W9.2).
 *
 * The writer owns three responsibilities and nothing else:
 *  - assign `audit_id`, compute the chain link against the actor's current head,
 *    and store the row (appends only),
 *  - page events newest-first for the viewer,
 *  - feed stored rows to the verifier in `@pv/audit`.
 *
 * No update path exists: an audit row that can be edited is an audit row that
 * can be rewritten. The Postgres migration additionally revokes UPDATE/DELETE
 * from the application role, so immutability is a database property (W9.5),
 * not a convention in this file.
 */

export interface AuditWriter {
  readonly kind: 'memory' | 'postgres';
  append(input: AuditEventInput, options?: { ownerKey?: string }): Promise<AuditEvent>;
  /** Events of one `(actor, actor_ref)` chain, oldest first, for verification. */
  listForVerification(actor: string, actorRef: string | null): Promise<AuditEvent[]>;
  /** Newest-first events for one owner's viewer, optionally filtered. */
  listEvents(options: { ownerKey: string; limit: number; request_id?: string }): Promise<AuditEvent[]>;
}

/**
 * The owner key an event is filed under.
 *
 * Owner and application events belong to a user; system and retention events
 * belong to the platform. The viewer only ever reads keys derived from the
 * authenticated session, so another owner's rows are unreachable by filter.
 */
export function ownerKeyFor(input: Pick<AuditEventInput, 'actor' | 'actor_ref'>): string {
  if (input.actor === 'system' || input.actor === 'retention_job') return `system:-`;
  return `${input.actor}:${input.actor_ref ?? '-'}`;
}

function chainKey(actor: string, actorRef: string | null): string {
  return `${actor}:${actorRef ?? '-'}`;
}

interface MemoryRow {
  event: AuditEvent;
  ownerKey: string;
  sequence: number;
}

export class MemoryAuditWriter implements AuditWriter {
  readonly kind = 'memory' as const;
  readonly #rows = new Map<string, MemoryRow>();
  #sequence = 0;

  async append(input: AuditEventInput, options?: { ownerKey?: string }): Promise<AuditEvent> {
    const actorRef = input.actor === 'system' || input.actor === 'retention_job' ? null : input.actor_ref;
    const key = chainKey(input.actor, actorRef);
    const head = await this.#head(key);
    const auditId = crypto.randomUUID();
    const { prev_hash, entry_hash } = appendToChain(input, auditId, head);
    const event: AuditEvent = { ...input, audit_id: auditId, prev_hash, entry_hash };
    this.#sequence += 1;
    this.#rows.set(auditId, {
      event,
      ownerKey: options?.ownerKey ?? ownerKeyFor(input),
      sequence: this.#sequence,
    });
    return event;
  }

  async #head(key: string): Promise<ChainPosition | null> {
    let head: MemoryRow | null = null;
    for (const row of this.#rows.values()) {
      if (chainKey(row.event.actor, row.event.actor_ref) !== key) continue;
      if (head === null || row.sequence > head.sequence) head = row;
    }
    return head === null ? null : { prev_hash: head.event.prev_hash, entry_hash: head.event.entry_hash };
  }

  async listForVerification(actor: string, actorRef: string | null): Promise<AuditEvent[]> {
    const key = chainKey(actor, actorRef);
    return [...this.#rows.values()]
      .filter((row) => chainKey(row.event.actor, row.event.actor_ref) === key)
      .map((row) => row.event)
      .sort((a, b) => a.timestamp.localeCompare(b.timestamp));
  }

  async listEvents(options: { ownerKey: string; limit: number; request_id?: string }): Promise<AuditEvent[]> {
    const all = [...this.#rows.values()]
      .filter((row) => row.ownerKey === options.ownerKey)
      .sort((a, b) => b.sequence - a.sequence)
      .map((row) => row.event);
    if (options.request_id === undefined) return all.slice(0, options.limit);
    // The audit input schema has no decision column by design: an event links
    // to a decision through the request it judged, so filtering must match the
    // request id exactly. (This filter used to accept `decision_id` and then
    // match `request_id !== null`, which returned essentially every event.)
    return all.filter((event) => event.request_id === options.request_id).slice(0, options.limit);
  }
}
