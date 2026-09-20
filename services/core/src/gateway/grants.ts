import { createHash, createHmac, timingSafeEqual } from 'node:crypto';
import { authorizationGrantSchema, type AuthorizationGrant } from '@pv/schemas';

/**
 * Authorization grants (`W7.3`).
 *
 * A grant is a signed, scope-limited, single-use token bound to one request,
 * one category, and the exact approved fields. What is persisted is the grant
 * record (`jti`-keyed); the token is returned once at issue time, so a
 * database read cannot yield a usable grant.
 *
 * Single-use is enforced at the gateway via the consumed marker; expiry,
 * replay, scope expansion and use-after-revocation are refused here, not at
 * the caller.
 */

const GRANT_TTL_MS = 5 * 60 * 1000;

export interface IssuedGrant {
  grant: AuthorizationGrant;
  /** Opaque token; shown once. */
  token: string;
  expires_at: string;
}

export interface GrantStore {
  save(grant: AuthorizationGrant): Promise<void>;
  find(jti: string): Promise<AuthorizationGrant | null>;
  /** Atomically consume; false when another caller got there first. */
  consume(jti: string): Promise<boolean>;
  revoke(jti: string): Promise<boolean>;
}

export class MemoryGrantStore implements GrantStore {
  readonly #rows = new Map<string, AuthorizationGrant>();

  async save(grant: AuthorizationGrant): Promise<void> {
    this.#rows.set(grant.jti, grant);
  }

  async find(jti: string): Promise<AuthorizationGrant | null> {
    return this.#rows.get(jti) ?? null;
  }

  async consume(jti: string): Promise<boolean> {
    const grant = this.#rows.get(jti);
    if (grant === undefined || grant.consumed_at !== null || grant.revoked_at !== null) return false;
    grant.consumed_at = new Date().toISOString();
    return true;
  }

  async revoke(jti: string): Promise<boolean> {
    const grant = this.#rows.get(jti);
    if (grant === undefined) return false;
    grant.revoked_at = new Date().toISOString();
    return true;
  }
}

export type GrantFailureReason =
  | 'grant_unknown'
  | 'grant_malformed'
  | 'grant_expired'
  | 'grant_consumed'
  | 'grant_revoked'
  | 'scope_expanded'
  | 'recipient_mismatch'
  | 'policy_changed';

export class GrantError extends Error {
  readonly reason: GrantFailureReason;

  constructor(reason: GrantFailureReason, detail: string) {
    super(detail);
    this.name = 'GrantError';
    this.reason = reason;
  }
}

/** HMAC over the canonical grant fields; the key is the core's own secret. */
function signGrant(payload: string, secret: string): string {
  return createHmac('sha256', secret).update(payload).digest('base64url');
}

function canonicalGrant(grant: AuthorizationGrant): string {
  return JSON.stringify({
    jti: grant.jti,
    request_id: grant.request_id,
    user_id: grant.user_id,
    decision_id: grant.decision_id,
    data_id: grant.data_id,
    data_category_id: grant.data_category_id,
    approved_fields: [...grant.approved_fields].sort(),
    recipient: grant.recipient,
    policy_version: grant.policy_version,
    issued_at: grant.issued_at,
    expires_at: grant.expires_at,
  });
}

export interface GrantIssuer {
  issue(input: {
    request_id: string;
    user_id: string;
    decision_id: string;
    data_id: string | null;
    data_category_id: string;
    approved_fields: readonly string[];
    recipient: string;
    policy_version: string;
    now: Date;
  }): Promise<IssuedGrant>;
  /** Verify, then atomically consume a presented token. */
  redeem(token: string, check: { fields: readonly string[]; recipient: string; policy_version: string; now: Date }): Promise<AuthorizationGrant>;
  /**
   * Give back a claim consumed by a redemption whose release then failed for
   * reasons the caller can cure (missing local values, a hiccup downstream).
   * A genuinely spent grant, an expired one and a revoked one stay consumed.
   */
  restore(jti: string): Promise<boolean>;
}

export class HmacGrantIssuer implements GrantIssuer {
  readonly #store: GrantStore;
  readonly #secretHex: string;

  constructor(store: GrantStore, secret: string) {
    this.#store = store;
    this.#secretHex = createHash('sha256').update(secret).digest('hex');
  }

  async issue(input: {
    request_id: string;
    user_id: string;
    decision_id: string;
    data_id: string | null;
    data_category_id: string;
    approved_fields: readonly string[];
    recipient: string;
    policy_version: string;
    now: Date;
  }): Promise<IssuedGrant> {
    const jti = crypto.randomUUID();
    const expiresAt = new Date(input.now.getTime() + GRANT_TTL_MS).toISOString();
    const draft: AuthorizationGrant = {
      jti,
      request_id: input.request_id,
      user_id: input.user_id,
      decision_id: input.decision_id,
      data_id: input.data_id,
      data_category_id: input.data_category_id,
      approved_fields: [...input.approved_fields],
      recipient: input.recipient,
      policy_version: input.policy_version,
      issued_at: input.now.toISOString(),
      expires_at: expiresAt,
      consumed_at: null,
      revoked_at: null,
    };
    const grant = authorizationGrantSchema.parse(draft);
    await this.#store.save(grant);
    const mac = signGrant(canonicalGrant(grant), this.#secretHex);
    return {
      grant,
      token: `${grant.jti}.${mac}`,
      expires_at: expiresAt,
    };
  }

  async redeem(
    token: string,
    check: { fields: readonly string[]; recipient: string; policy_version: string; now: Date },
  ): Promise<AuthorizationGrant> {
    const dot = token.indexOf('.');
    if (dot <= 0) throw new GrantError('grant_malformed', 'the grant token is not in the expected form');
    const jti = token.slice(0, dot);
    const mac = token.slice(dot + 1);

    const grant = await this.#store.find(jti);
    if (grant === null) throw new GrantError('grant_unknown', 'no grant with this identifier exists');

    const expected = signGrant(canonicalGrant(grant), this.#secretHex);
    const macBytes = Buffer.from(mac);
    const expectedBytes = Buffer.from(expected);
    if (macBytes.length !== expectedBytes.length || !timingSafeEqual(macBytes, expectedBytes)) {
      throw new GrantError('grant_malformed', 'the grant token does not match the recorded grant');
    }

    if (grant.revoked_at !== null) throw new GrantError('grant_revoked', 'the grant was revoked');
    if (Date.parse(grant.expires_at) <= check.now.getTime()) {
      throw new GrantError('grant_expired', 'the grant expired before use');
    }

    const requested = new Set(check.fields);
    const approved = new Set(grant.approved_fields);
    for (const field of requested) {
      if (!approved.has(field)) {
        throw new GrantError('scope_expanded', 'the requested fields exceed the approved scope');
      }
    }
    if (check.recipient !== grant.recipient) {
      throw new GrantError('recipient_mismatch', 'the recipient does not match the grant');
    }
    if (check.policy_version !== grant.policy_version) {
      throw new GrantError('policy_changed', 'the policy version changed after the grant was issued');
    }

    if (!(await this.#store.consume(grant.jti))) {
      throw new GrantError('grant_consumed', 'the grant was already used');
    }
    return grant;
  }

  async restore(jti: string): Promise<boolean> {
    const grant = await this.#store.find(jti);
    if (grant === null) return false;
    if (grant.revoked_at !== null) return false;
    if (grant.consumed_at === null) return false;
    if (Date.parse(grant.expires_at) <= Date.now()) return false;
    grant.consumed_at = null;
    return true;
  }
}
