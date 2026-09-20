import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { rulesetSchema, type Rule, type Ruleset, type UserRuleInput } from '@pv/schemas';

/**
 * Critical rule registry (`T023`, W5.5).
 *
 * The critical class is system-owned: these rules cannot be bypassed through
 * Force Allow, and the union is enforced in the evaluator and the gateway rather
 * than only in a user interface (`D-029`).
 *
 * The set lives here, next to the evaluator, so the decision engine, the gateway
 * and the dashboard all read one definition. A rule may only join this set by
 * being added to the versioned ruleset file **and** named here, which is a
 * deliberate two-step change.
 */
export const CRITICAL_RULE_IDS: ReadonlySet<string> = new Set([
  'R-CRITICAL-MEDICAL',
  'R-CRITICAL-FINANCIAL',
  'R-CRITICAL-CREDENTIAL',
]);

/** Highest priority a user rule may carry, below every system rule that blocks. */
export const MAX_USER_RULE_PRIORITY = 8999;

export class RulesetError extends Error {
  readonly detail: string;

  constructor(message: string, detail: string) {
    super(message);
    this.name = 'RulesetError';
    this.detail = detail;
  }
}

/**
 * Canonical form used for the checksum.
 *
 * Key order is normalised by rebuilding each object, and rules are sorted by id,
 * so reordering the rules in the file does not change the checksum while any
 * substantive edit does.
 */
export function canonicalRuleset(rules: readonly Rule[]): string {
  const sorted = [...rules].sort((a, b) => (a.rule_id < b.rule_id ? -1 : a.rule_id > b.rule_id ? 1 : 0));
  return JSON.stringify(
    sorted.map((rule) => ({
      rule_id: rule.rule_id,
      ruleset_version: rule.ruleset_version,
      condition: rule.condition,
      effect: rule.effect,
      priority: rule.priority,
      scope: rule.scope,
      rationale: rule.rationale,
      override_class: rule.override_class,
      origin: rule.origin,
      reason_code: rule.reason_code,
      expires_at: rule.expires_at,
    })),
  );
}

export function rulesetChecksum(rules: readonly Rule[]): string {
  return createHash('sha256').update(canonicalRuleset(rules)).digest('hex');
}

/**
 * Load and validate a ruleset file.
 *
 * A malformed rule file stops startup with the file and the offending field
 * named: silently skipping a rule would mean running with a policy nobody chose.
 */
export function loadRuleset(path: string): Ruleset {
  let raw: string;
  try {
    raw = readFileSync(path, 'utf8');
  } catch (error) {
    throw new RulesetError(
      'the ruleset file could not be read',
      `${path}: ${error instanceof Error ? error.message : 'unknown error'}`,
    );
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (error) {
    throw new RulesetError('the ruleset is not valid JSON', `${path}: ${error instanceof Error ? error.message : ''}`);
  }

  const result = rulesetSchema.safeParse(parsed);
  if (!result.success) {
    const fields = result.error.issues
      .map((issue) => `${issue.path.map(String).join('.') || '<root>'}: ${issue.message}`)
      .join('; ');
    throw new RulesetError('the ruleset does not match the rule schema', `${path}: ${fields}`);
  }

  const expected = rulesetChecksum(result.data.rules);
  if (expected !== result.data.checksum) {
    throw new RulesetError(
      'the ruleset checksum does not match its rules',
      `${path}: recorded ${result.data.checksum}, computed ${expected}`,
    );
  }

  return result.data;
}

/**
 * Turn a validated user rule proposal into a stored rule.
 *
 * The caller cannot supply `origin` or `override_class`, and the priority is
 * capped below the system range, so the stored rule is structurally incapable of
 * claiming the critical class (W5.4).
 */
export function toStoredUserRule(
  input: UserRuleInput,
  options: { rule_id: string; policy_version: string },
): Rule {
  if (input.priority > MAX_USER_RULE_PRIORITY) {
    throw new RulesetError(
      'the priority is above the user-rule range',
      `a user rule may not exceed priority ${MAX_USER_RULE_PRIORITY}`,
    );
  }
  const categories = input.effect === 'allow' ? input.scope.data_categories : null;
  if (categories !== null && categories.length === 0) {
    throw new RulesetError(
      'an allow rule must name the categories it applies to',
      'an unrestricted allow would authorise data the request did not ask for',
    );
  }
  return {
    rule_id: options.rule_id,
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
  };
}
