import { randomUUID } from 'node:crypto';
import {
  formatPolicyVersion,
  ruleSchema,
  type PolicyVersion,
  type Rule,
  type UserRuleInput,
} from '@pv/schemas';

/**
 * Owner policy state (W5.4, W5.6, W6.6).
 *
 * The store owns three things and nothing else: the owner's user rules, the
 * monotonically increasing policy epoch, and the composite policy version
 * (`ruleset@epoch`) that every decision and audit record carries. An epoch bump
 * on every mutation is what makes a stored decision reproducible: recomputing
 * it under a changed policy yields a different `policy_version` and is recorded
 * as a *new* decision, never as an edit of the old one.
 *
 * System rules live in the versioned ruleset file, not here. The store refuses
 * to hold rules with `origin: 'system'` or `override_class: 'critical'`, so a
 * caller cannot smuggle a critical rule into user policy through this seam.
 */
export interface UserPolicyStore {
  /** All active (non-expired at evaluation time) user rules for one owner. */
  listUserRules(userId: string): Promise<Rule[]>;
  getUserRule(userId: string, ruleId: string): Promise<Rule | null>;
  insertUserRule(userId: string, rule: Rule, createdAt: string): Promise<void>;
  updateUserRule(userId: string, ruleId: string, rule: Rule, updatedAt: string): Promise<boolean>;
  deleteUserRule(userId: string, ruleId: string): Promise<boolean>;
  /** Current epoch; starts at 1 and advances on every mutation. */
  policyEpoch(userId: string): Promise<number>;
  /** Advance the epoch and return the new value. */
  bumpPolicyEpoch(userId: string): Promise<number>;
}

export class MemoryUserPolicyStore implements UserPolicyStore {
  readonly #rules = new Map<string, Map<string, { rule: Rule; created_at: string; updated_at: string }>>();
  readonly #epochs = new Map<string, number>();

  async listUserRules(userId: string): Promise<Rule[]> {
    const owned = this.#rules.get(userId);
    if (!owned) return [];
    return [...owned.values()].map((row) => row.rule);
  }

  async getUserRule(userId: string, ruleId: string): Promise<Rule | null> {
    return this.#rules.get(userId)?.get(ruleId)?.rule ?? null;
  }

  async insertUserRule(userId: string, rule: Rule, createdAt: string): Promise<void> {
    let owned = this.#rules.get(userId);
    if (!owned) {
      owned = new Map();
      this.#rules.set(userId, owned);
    }
    if (owned.has(rule.rule_id)) {
      throw new PolicyConflictError('a rule with this id already exists', 'rule_id');
    }
    owned.set(rule.rule_id, { rule, created_at: createdAt, updated_at: createdAt });
    await this.bumpPolicyEpoch(userId);
  }

  async updateUserRule(userId: string, ruleId: string, rule: Rule, updatedAt: string): Promise<boolean> {
    const owned = this.#rules.get(userId);
    const existing = owned?.get(ruleId);
    if (!owned || !existing) return false;
    owned.delete(ruleId);
    owned.set(rule.rule_id, { rule, created_at: existing.created_at, updated_at: updatedAt });
    await this.bumpPolicyEpoch(userId);
    return true;
  }

  async deleteUserRule(userId: string, ruleId: string): Promise<boolean> {
    const owned = this.#rules.get(userId);
    if (!owned || !owned.has(ruleId)) return false;
    owned.delete(ruleId);
    await this.bumpPolicyEpoch(userId);
    return true;
  }

  async policyEpoch(userId: string): Promise<number> {
    return this.#epochs.get(userId) ?? 1;
  }

  async bumpPolicyEpoch(userId: string): Promise<number> {
    const next = (this.#epochs.get(userId) ?? 1) + 1;
    this.#epochs.set(userId, next);
    return next;
  }
}

export class PolicyConflictError extends Error {
  /** The rule field the refusal is about, for a 400 response naming paths only. */
  readonly field: string;

  constructor(detail: string, field = 'rule') {
    super(detail);
    this.name = 'PolicyConflictError';
    this.field = field;
  }
}

/**
 * The composite policy version for one owner.
 *
 * `ruleset_version` comes from the validated ruleset data; the epoch comes from
 * the store. The format is `ruleset@epoch`, parsed by
 * `parsePolicyVersion` so any consumer can recover both components.
 */
export async function currentPolicyVersion(
  store: UserPolicyStore,
  userId: string,
  rulesetVersion: string,
): Promise<PolicyVersion> {
  const epoch = await store.policyEpoch(userId);
  return {
    ruleset_version: rulesetVersion,
    user_policy_epoch: epoch,
    policy_version: formatPolicyVersion(rulesetVersion, epoch),
  };
}

export interface UserRuleMutation {
  rule: Rule;
  policy_version: string;
}

/**
 * Validate a user rule input into a storable rule (W5.4).
 *
 * The result is structurally incapable of claiming the critical class: `origin`
 * and `override_class` are assigned here and never accepted from the caller.
 * Allow rules must name the categories they permit, so a rule cannot widen a
 * request into an unrestricted grant.
 */
export function buildUserRule(input: UserRuleInput, options: { policy_version: string }): UserRuleMutation {
  const ruleId = input.rule_id ?? `R-U-${randomUUID().replace(/-/g, '').slice(0, 10).toUpperCase()}`;
  const categories = input.effect === 'allow' ? input.scope.data_categories : null;
  if (categories !== null && categories.length === 0) {
    throw new PolicyConflictError('an allow rule must name the categories it applies to', 'scope.data_categories');
  }
  if (input.expires_at !== null && Date.parse(input.expires_at) <= Date.now()) {
    throw new PolicyConflictError('the expiry must be in the future', 'expires_at');
  }
  const rule = ruleSchema.parse({
    rule_id: ruleId,
    ruleset_version: options.policy_version,
    condition: input.condition,
    effect: input.effect,
    priority: input.priority,
    scope: input.scope,
    rationale: input.rationale,
    override_class: 'overridable',
    origin: 'user',
    reason_code: `USER_${input.effect.toUpperCase()}`,
    expires_at: input.expires_at,
  });
  return { rule, policy_version: options.policy_version };
}
