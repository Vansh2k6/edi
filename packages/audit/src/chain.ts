import { createHash } from 'node:crypto';
import type { AuditEvent, AuditEventInput } from '@pv/schemas';

/**
 * Audit chain construction and verification (W9.2, T038).
 *
 * The chain is per-actor: `prev_hash` links each record to the previous record
 * for the same `(actor, actor_ref)`, so deleting one row (or the retention
 * job's work) breaks the chain for that actor only, and the tombstone explains
 * the gap. A single global chain would make every deletion look like tampering.
 *
 * `entry_hash` covers every field of the record including the id and timestamp,
 * which is what makes an in-place SQL edit detectable.
 */

export interface ChainPosition {
  prev_hash: string | null;
  entry_hash: string;
}

export function auditEntryHash(input: AuditEventInput & { audit_id: string; prev_hash: string | null }): string {
  const canonical = JSON.stringify({
    audit_id: input.audit_id,
    request_id: input.request_id,
    timestamp: input.timestamp,
    actor: input.actor,
    actor_ref: input.actor_ref,
    origin_domain: input.origin_domain,
    requested_categories: [...input.requested_categories].sort(),
    domain_intelligence_summary: input.domain_intelligence_summary,
    matched_rules: [...input.matched_rules].sort(),
    risk_level: input.risk_level,
    decision: input.decision,
    override: input.override,
    // Normalised so the hash covers the W6.5/W6.4/W7.2 fields whether or not
    // an older event carried them: an audit row whose reason could be edited
    // without breaking the chain would not be an audit row.
    override_reason: input.override_reason ?? null,
    refusal_reason: input.refusal_reason ?? null,
    consent_id: input.consent_id ?? null,
    classified_categories: [...(input.classified_categories ?? [])].sort(),
    policy_version: input.policy_version,
    prev_hash: input.prev_hash,
  });
  return createHash('sha256').update(canonical).digest('hex');
}

/** The chain key an event belongs to. */
export function chainKeyOf(event: { actor: AuditEvent['actor']; actor_ref: string | null }): string {
  return `${event.actor}:${event.actor_ref ?? '-'}`;
}

export interface AppendChainResult {
  prev_hash: string | null;
  entry_hash: string;
}

/**
 * Compute the hash fields for a new event appended to its actor's chain.
 *
 * `audit_id` is supplied by the caller (the repository that will store the row)
 * so the hash always covers an identifier that actually exists in storage.
 * `head` is the current `entry_hash` of the actor's last record, or null when
 * this is the first. The caller is responsible for serialising appends per
 * chain: two writers picking the same head would fork the chain, so the
 * repository guards this with a per-chain insert lock (or a DB constraint).
 */
export function appendToChain(input: AuditEventInput, auditId: string, head: ChainPosition | null): AppendChainResult {
  const prev_hash = head === null || head.entry_hash === '' ? null : head.entry_hash;
  return { prev_hash, entry_hash: auditEntryHash({ ...input, audit_id: auditId, prev_hash }) };
}

export type ChainProblem =
  | { kind: 'genesis_without_null_prev'; audit_id: string }
  | { kind: 'prev_hash_mismatch'; audit_id: string; expected_prev: string | null; found: string | null }
  | { kind: 'entry_hash_mismatch'; audit_id: string; expected: string; found: string };

export interface ActorChainVerification {
  chain_key: string;
  records: number;
  intact: boolean;
  problems: ChainProblem[];
}

export interface ChainVerification {
  intact: boolean;
  records: number;
  /** One entry per `(actor, actor_ref)` chain found in the input. */
  chains: ActorChainVerification[];
  problems: ChainProblem[];
  /** First broken link, for the verification endpoint's report. */
  first_broken: (ChainProblem & { audit_id: string }) | null;
}

/**
 * Verify chains, grouped per actor.
 *
 * Genesis must carry `prev_hash: null`; every later record must name the
 * previous record's `entry_hash`, and every record's own `entry_hash` must
 * recompute exactly. Events are grouped by `(actor, actor_ref)` and ordered by
 * timestamp inside each group, so interleaved actors verify independently and
 * the caller may pass records in any order. Verification continues past the
 * first problem so the operator can see how far the damage reaches.
 */
export function verifyChain(events: readonly AuditEvent[]): ChainVerification {
  const groups = new Map<string, AuditEvent[]>();
  for (const event of events) {
    const key = chainKeyOf(event);
    const group = groups.get(key);
    if (group) group.push(event);
    else groups.set(key, [event]);
  }

  const problems: ChainProblem[] = [];
  let first: (ChainProblem & { audit_id: string }) | null = null;
  const chains: ActorChainVerification[] = [];

  for (const [chain_key, group] of [...groups.entries()].sort((a, b) => (a[0] < b[0] ? -1 : 1))) {
    const sorted = [...group].sort((a, b) => a.timestamp.localeCompare(b.timestamp));
    const chainProblems: ChainProblem[] = [];
    let expectedPrev: string | null = null;

    for (const event of sorted) {
      if (expectedPrev === null && event.prev_hash !== null) {
        chainProblems.push({ kind: 'genesis_without_null_prev', audit_id: event.audit_id });
      }
      if (expectedPrev !== null && event.prev_hash !== expectedPrev) {
        chainProblems.push({
          kind: 'prev_hash_mismatch',
          audit_id: event.audit_id,
          expected_prev: expectedPrev,
          found: event.prev_hash,
        });
      }
      const recomputed = auditEntryHash({ ...event });
      if (recomputed !== event.entry_hash) {
        chainProblems.push({
          kind: 'entry_hash_mismatch',
          audit_id: event.audit_id,
          expected: recomputed,
          found: event.entry_hash,
        });
      }
      expectedPrev = event.entry_hash;
    }

    for (const problem of chainProblems) {
      problems.push(problem);
      if (first === null) first = problem;
    }
    chains.push({ chain_key, records: sorted.length, intact: chainProblems.length === 0, problems: chainProblems });
  }

  return {
    intact: problems.length === 0,
    records: events.length,
    chains,
    problems,
    first_broken: first,
  };
}
