import { createHmac, randomUUID, timingSafeEqual } from 'node:crypto';
import { nodeCipher, openString, type KeyProvider } from '@pv/crypto';
import type { DisclosureFailure, DisclosureResult, VaultEntry } from '@pv/schemas';
import { GrantError, type GrantIssuer } from './grants.js';
import type { AuditWriter } from '../audit-writer.js';
import type { VaultRepository } from '../repositories/vault-repository.js';
import type { ConsentStore } from '../consent-store.js';

/**
 * Vault gateway (`T028`--`T030`, W7.1, W7.2).
 *
 * The single entry point for releasing protected data. Everything upstream in
 * the pipeline is advisory; this module is authoritative and fails closed: it
 * re-derives authorization at disclosure time from the presented grant, the
 * current consent state and the current policy version, and releases only the
 * approved minimum. Every successful release writes one audit event.
 *
 * The tests/security/import-boundaries suite fails the build if any module
 * outside this directory imports the release helpers directly (T029).
 */

/** Key material the gateway needs to open a server-tier entry, read-only. */
export interface ServerTierEntry {
  ciphertext: string;
  wrapped_dek: string;
  key_id: string;
  kek_ref: string;
  /**
   * The data id the client sealed the blob under (`pv_seal_data_id`), when the
   * entry records one. Decryption verifies the binding, so this is a lookup
   * hint, never an authorization.
   */
  seal_data_id: string | null;
}

/**
 * The one seam through which the gateway reads stored ciphertext.
 *
 * Implemented by the vault repositories. No other module may import or call
 * it: keeping ciphertext access behind the gateway is what makes the import
 * boundary test meaningful.
 */
export interface ServerTierEntryReader {
  getServerTierEntry(userId: string, dataId: string): Promise<ServerTierEntry | null>;
}

export type ReleaseResult =
  | { ok: true; result: DisclosureResult }
  | { ok: false; failure: DisclosureFailure; http_status: number };

export interface GatewayDependencies {
  repository: VaultRepository;
  serverEntries: ServerTierEntryReader;
  grants: GrantIssuer;
  audit: AuditWriter;
  keyProvider: KeyProvider;
  /** Secret for grants and release receipts; injected so tests can pin it. */
  grantSecret: string;
  /**
   * Shared consent state (W8.5). When absent the gateway keeps its own
   * in-memory map, which is enough for callers that only exercise the
   * disclosure path; the HTTP app always supplies the store the consent
   * routes write, so the dashboard and the gateway cannot disagree.
   */
  consents?: ConsentStore;
  now?: () => Date;
}

const failureStatus: Record<DisclosureFailure['reason'], number> = {
  grant_unknown: 404,
  grant_malformed: 400,
  grant_expired: 401,
  grant_consumed: 401,
  grant_revoked: 401,
  scope_expanded: 403,
  recipient_mismatch: 403,
  policy_changed: 409,
  not_authorized: 403,
  consent_missing: 403,
  consent_revoked: 403,
  entry_missing: 404,
  local_data_unavailable: 409,
};

export class VaultGateway {
  readonly #deps: GatewayDependencies;
  readonly #consents = new Map<string, { status: 'Active' | 'Revoked'; consentId: string | null }>();

  constructor(deps: GatewayDependencies) {
    this.#deps = deps;
  }

  /**
   * Release the approved fields of one entry.
   *
   * The grant is verified and atomically consumed here, consent is re-checked
   * at disclosure time, and the release writes one audit event. A local-tier
   * entry has no ciphertext in the core: the caller presents the values the
   * extension already fetched under the owner's gesture, and the gateway still
   * authorizes, bounds and audits the disclosure. A server-tier entry is
   * decrypted inside the core through the `KeyProvider`.
   */
  async authorizeDisclosure(input: {
    user_id: string;
    grant_token: string;
    fields: readonly string[];
    recipient: string;
    policy_version: string;
    /** Local-tier values already fetched through the extension bridge. */
    local_values?: Record<string, string> | undefined;
  }): Promise<ReleaseResult> {
    const now = (this.#deps.now ?? (() => new Date()))();

    try {
      const grant = await this.#deps.grants.redeem(input.grant_token, {
        fields: input.fields,
        recipient: input.recipient,
        policy_version: input.policy_version,
        now,
      });

      // The grant is bound to its owner: a stolen token presented under another
      // session is refused even though the signature verifies. The grant was
      // consumed by the redeem, so the refusal is recorded under the granted
      // owner's chain.
      if (grant.user_id !== input.user_id) {
        return this.#refused(grant, 'not_authorized', 'the grant belongs to another owner', input.policy_version);
      }

      const consentState = await this.#consentStateFor(grant.user_id, grant.data_category_id);
      if (consentState !== undefined && consentState.status !== 'Active') {
        return this.#refused(
          grant,
          'consent_revoked',
          'consent for this category is not active at disclosure time',
          input.policy_version,
        );
      }

      let entry: VaultEntry | null = null;
      if (grant.data_id !== null) {
        entry = await this.#deps.repository.getEntry(grant.user_id, grant.data_id);
        if (entry === null) {
          return this.#refused(grant, 'entry_missing', 'the vault entry for this grant no longer exists', input.policy_version);
        }
      }

      const released = await this.#release(grant, entry, input.local_values);
      if (!released.ok) {
        // A refused release must not consume the grant: the owner may retry
        // with the values the first attempt lacked.
        await this.#deps.grants.restore(grant.jti);
        return this.#refused(grant, released.failure, released.detail, input.policy_version);
      }

      const result: DisclosureResult = {
        disclosure_id: randomUUID(),
        released_fields: [...input.fields].sort(),
        data_category_id: grant.data_category_id,
        recipient: input.recipient,
        values: released.values,
        storage_tier: entry === null ? 'local' : entry.storage_tier === 'server' ? 'server' : 'local',
        disclosed_at: now.toISOString(),
      };

      // One audit row per release, filed under the owner's key so the viewer
      // finds it. The recipient sees only the released values, never the
      // minimization metadata behind the decision.
      await this.#deps.audit.append(
        {
          request_id: grant.request_id,
          timestamp: now.toISOString(),
          actor: 'application',
          actor_ref: input.recipient,
          origin_domain: input.recipient,
          requested_categories: [grant.data_category_id],
          domain_intelligence_summary: null,
          matched_rules: [],
          risk_level: null,
          decision: null,
          override: false,
          policy_version: input.policy_version,
          ...(consentState?.consentId === null || consentState?.consentId === undefined ? {} : { consent_id: consentState.consentId }),
        },
        { ownerKey: `owner:${grant.user_id}` },
      );

      return { ok: true, result };
    } catch (error) {
      if (error instanceof GrantError) {
        // Refusals are audited too: a refused disclosure attempt that left no
        // trace would be indistinguishable from one that never happened.
        return this.#refusedGrantError(error, input);
      }
      throw error;
    }
  }

  /**
   * Owner self-reveal (T033): the dashboard showing the owner their own
   * values. It is an audited, re-authenticated act - never a silent read -
   * and it releases only through the same decrypt path as a disclosure, so
   * the gateway stays the single place vault plaintext is opened (T029).
   * A local-tier entry has no ciphertext in the core: the honest answer is
   * `local_data_unavailable`, not fabricated values.
   */
  async revealForOwner(input: {
    user_id: string;
    data_id: string;
    /** The explicit gesture + re-auth confirmation from the reveal request. */
    confirm_reauth: boolean;
    policy_version: string;
  }): Promise<
    | { ok: true; result: { data_id: string; data_category_id: string; storage_tier: 'server'; values: Record<string, string> } }
    | { ok: false; failure: 'reauth_required' | 'entry_missing' | 'local_data_unavailable'; http_status: number; detail: string }
  > {
    const refuse = async (
      failure: 'reauth_required' | 'entry_missing' | 'local_data_unavailable',
      httpStatus: number,
      detail: string,
      categoryId: string | null,
    ) => {
      await this.#deps.audit.append(
        {
          request_id: null,
          timestamp: new Date().toISOString(),
          actor: 'owner',
          actor_ref: input.user_id,
          origin_domain: null,
          requested_categories: categoryId === null ? [] : [categoryId],
          domain_intelligence_summary: null,
          matched_rules: [],
          risk_level: null,
          decision: null,
          override: false,
          refusal_reason: failure,
          policy_version: input.policy_version,
        },
        { ownerKey: `owner:${input.user_id}` },
      );
      return { ok: false as const, failure, http_status: httpStatus, detail };
    };

    if (!input.confirm_reauth) {
      return refuse('reauth_required', 403, 'a reveal requires the explicit re-auth confirmation', null);
    }

    const entry = await this.#deps.repository.getEntry(input.user_id, input.data_id);
    if (entry === null) {
      return refuse('entry_missing', 404, 'no such vault entry for this owner', null);
    }
    if (entry.storage_tier !== 'server') {
      return refuse('local_data_unavailable', 409, 'the values of a local-tier entry never reach the core', entry.data_category_id);
    }

    const stored = await this.#deps.serverEntries.getServerTierEntry(input.user_id, entry.data_id);
    if (stored === null) {
      return refuse('entry_missing', 404, 'the entry exists but its key material is unavailable', entry.data_category_id);
    }
    const sealDataId = stored.seal_data_id ?? entry.data_id;
    try {
      const dek = await this.#deps.keyProvider.unwrapDek({
        key_ref: stored.key_id,
        kek_ref: stored.kek_ref,
        algorithm: 'AES-256-GCM',
        wrapped: stored.wrapped_dek,
      });
      const blob = Uint8Array.from(Buffer.from(stored.ciphertext, 'base64'));
      const plaintext = await openString(
        nodeCipher,
        { data_id: sealDataId, user_id: input.user_id, data_category_id: entry.data_category_id },
        dek,
        blob,
      );
      const values = JSON.parse(plaintext) as Record<string, string>;

      await this.#deps.audit.append(
        {
          request_id: null,
          timestamp: new Date().toISOString(),
          actor: 'owner',
          actor_ref: input.user_id,
          origin_domain: null,
          requested_categories: [entry.data_category_id],
          domain_intelligence_summary: null,
          matched_rules: [],
          risk_level: null,
          decision: null,
          override: false,
          policy_version: input.policy_version,
        },
        { ownerKey: `owner:${input.user_id}` },
      );
      return {
        ok: true,
        result: { data_id: entry.data_id, data_category_id: entry.data_category_id, storage_tier: 'server', values },
      };
    } catch {
      return refuse('entry_missing', 404, 'the stored ciphertext failed to open under the current key', entry.data_category_id);
    }
  }

  /**
   * Record one refusal under the granted owner's chain. The grant fields name
   * the attempt without echoing any value that was about to be released.
   */
  async #refused(
    grant: { request_id: string; user_id: string; data_category_id: string },
    reason: DisclosureFailure['reason'],
    detail: string,
    policyVersion: string,
  ): Promise<ReleaseResult> {
    await this.#deps.audit.append(
      {
        request_id: grant.request_id,
        timestamp: new Date().toISOString(),
        actor: 'application',
        actor_ref: grant.user_id,
        origin_domain: null,
        requested_categories: [grant.data_category_id],
        domain_intelligence_summary: null,
        matched_rules: [],
        risk_level: null,
        decision: null,
        override: false,
        refusal_reason: reason,
        policy_version: policyVersion,
      },
      { ownerKey: `owner:${grant.user_id}` },
    );
    return { ok: false, failure: { refused: true, reason, detail }, http_status: failureStatus[reason]! };
  }

  /** A refusal before the grant could be resolved: the owner is still known. */
  async #refusedGrantError(error: GrantError, input: { user_id: string; policy_version: string; recipient: string }): Promise<ReleaseResult> {
    await this.#deps.audit.append(
      {
        request_id: null,
        timestamp: new Date().toISOString(),
        actor: 'application',
        actor_ref: input.user_id,
        origin_domain: input.recipient,
        requested_categories: [],
        domain_intelligence_summary: null,
        matched_rules: [],
        risk_level: null,
        decision: null,
        override: false,
        refusal_reason: error.reason,
        policy_version: input.policy_version,
      },
      { ownerKey: `owner:${input.user_id}` },
    );
    return { ok: false, failure: { refused: true, reason: error.reason, detail: error.message }, http_status: failureStatus[error.reason]! };
  }

  /**
   * Consent re-check at disclosure time.
   *
   * Consent management is a Phase 8 surface; the check exists now and consults
   * the gateway's own registry, so a consent revoked between decision and
   * disclosure is refused rather than silently trusted from decision time.
   * When a consent record id is known it travels into the audit event, so the
   * disclosure names the exact consent it relied on.
   */
  async consentActive(userId: string, categoryId: string): Promise<boolean> {
    const state = this.#consents.get(`${userId}:${categoryId}`);
    return state === undefined ? true : state.status === 'Active';
  }

  /** Record consent state for the disclosure-time check (core-internal seam). */
  async setConsent(userId: string, categoryId: string, status: 'Active' | 'Revoked', consentId?: string): Promise<void> {
    const store = this.#deps.consents;
    if (store !== undefined) {
      const existing = await store.getConsent(userId, categoryId);
      await store.upsertConsent({
        user_id: userId,
        data_category_id: categoryId,
        status,
        // A revoke keeps the id of the grant it revokes, so audit rows stay traceable.
        consent_id: consentId ?? existing?.consent_id ?? null,
        updated_at: new Date().toISOString(),
      });
      return;
    }
    this.#consents.set(`${userId}:${categoryId}`, { status, consentId: consentId ?? null });
  }

  async #consentStateFor(userId: string, categoryId: string): Promise<{ status: 'Active' | 'Revoked'; consentId: string | null } | undefined> {
    const store = this.#deps.consents;
    if (store !== undefined) {
      const record = await store.getConsent(userId, categoryId);
      return record === null ? undefined : { status: record.status, consentId: record.consent_id };
    }
    return this.#consents.get(`${userId}:${categoryId}`);
  }

  /**
   * Produce a tamper-evident release receipt.
   *
   * An HMAC over the canonical release facts, keyed by the core's grant
   * secret. It lets the owner or an auditor confirm that a claimed disclosure
   * came from the gateway without exposing the released values.
   */
  receipt(result: DisclosureResult, request_id: string): string {
    const payload = JSON.stringify({
      disclosure_id: result.disclosure_id,
      request_id,
      released_fields: [...result.released_fields].sort(),
      recipient: result.recipient,
      disclosed_at: result.disclosed_at,
    });
    const mac = createHmac('sha256', this.#deps.grantSecret).update(payload).digest('base64url');
    return `${Buffer.from(payload).toString('base64url')}.${mac}`;
  }

  /** Verify a receipt against its embedded payload (test/audit helper). */
  verifyReceipt(receipt: string): boolean {
    const dot = receipt.indexOf('.');
    if (dot <= 0) return false;
    const payloadB64 = receipt.slice(0, dot);
    const mac = receipt.slice(dot + 1);
    let payload: string;
    try {
      payload = Buffer.from(payloadB64, 'base64url').toString('utf8');
    } catch {
      return false;
    }
    const expected = createHmac('sha256', this.#deps.grantSecret).update(payload).digest('base64url');
    const a = Buffer.from(mac);
    const b = Buffer.from(expected);
    return a.length === b.length && timingSafeEqual(a, b);
  }

  async #release(
    grant: { data_id: string | null; user_id: string; data_category_id: string; approved_fields: readonly string[] },
    entry: VaultEntry | null,
    localValues: Record<string, string> | undefined,
  ): Promise<{ ok: true; values: Record<string, string> | null } | { ok: false; failure: DisclosureFailure['reason']; detail: string }> {
    if (entry === null || entry.storage_tier === 'local') {
      if (localValues === undefined) {
        return { ok: false, failure: 'local_data_unavailable', detail: 'the local-tier values were not presented' };
      }
      const values: Record<string, string> = {};
      for (const field of grant.approved_fields) {
        if (field in localValues) values[field] = localValues[field]!;
      }
      return { ok: true, values };
    }

    // Server tier: decrypt inside the core through the KeyProvider (W7.2).
    //
    // The client seals its blob under a binding it chose at seal time (the
    // storage protocol records it as `pv_seal_data_id` in client_metadata);
    // the server-assigned row id is not necessarily that binding. The
    // release therefore reconstructs the seal binding from the entry's
    // metadata, and the authenticated decryption itself verifies the match:
    // a blob whose AAD does not equal this binding fails closed with an
    // opaque entry_missing rather than releasing anything.
    const stored = await this.#deps.serverEntries.getServerTierEntry(grant.user_id, entry.data_id);
    if (stored === null) {
      return { ok: false, failure: 'entry_missing', detail: 'the entry exists but its key material is unavailable' };
    }
    const sealDataId = stored.seal_data_id ?? entry.data_id;
    try {
      const dek = await this.#deps.keyProvider.unwrapDek({
        key_ref: stored.key_id,
        kek_ref: stored.kek_ref,
        algorithm: 'AES-256-GCM',
        wrapped: stored.wrapped_dek,
      });
      const blob = Uint8Array.from(Buffer.from(stored.ciphertext, 'base64'));
      const plaintext = await openString(
        nodeCipher,
        // The seal binding, not the row id: releasing under the wrong binding
        // is refused by the cipher, not by a trustable metadata claim.
        { data_id: sealDataId, user_id: grant.user_id, data_category_id: grant.data_category_id },
        dek,
        blob,
      );
      const parsed = JSON.parse(plaintext) as Record<string, string>;
      const values: Record<string, string> = {};
      for (const field of grant.approved_fields) {
        if (field in parsed) values[field] = parsed[field]!;
      }
      return { ok: true, values };
    } catch {
      // Never surface partial plaintext or the underlying crypto detail.
      return { ok: false, failure: 'entry_missing', detail: 'the stored ciphertext failed to open under the current key' };
    }
  }
}
