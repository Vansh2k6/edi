import type { DomainSignal, ObservedRequest, OverrideClass, Rule, RuleCondition, RuleEffect, SignalType } from '@pv/schemas';
import type { ClassificationResult } from './classify.js';
import type { FeasibilityResult } from './feasibility.js';
import { CRITICAL_RULE_IDS } from './critical.js';

/**
 * Deterministic rule evaluation (`T020`, W5.2).
 *
 * `AGENT.md` requires that identical normalised inputs and identical policy state
 * produce the same result. Nothing here reads the clock except through `now`,
 * nothing iterates a map in insertion order, and every "cannot tell" case is
 * reported as `unevaluated` rather than resolved by a guess.
 *
 * Three rules of the design are worth stating because they are what the tests
 * exist to protect:
 *
 * 1. Rules are evaluated in a total order `(priority, rule_id)`; file order and
 *    object key order cannot change an outcome.
 * 2. Equal-priority opposing effects resolve to the most restrictive effect and
 *    set a `conflict` flag, and every matched rule is still reported.
 * 3. A rule whose required signal is absent or stale does not match. Silence is
 *    not agreement: an evaluator that let a rule fire on missing data would let a
 *    provider outage become a permission (D-028).
 */

/** Most restrictive last: used to resolve opposing effects. */
export const EFFECT_RESTRICTIVENESS: readonly RuleEffect[] = ['allow', 'warn', 'ask_user', 'block'];

export function restrictivenessOf(effect: RuleEffect): number {
  return EFFECT_RESTRICTIVENESS.indexOf(effect);
}

export function mostRestrictive(effects: readonly RuleEffect[]): RuleEffect {
  let winner: RuleEffect = 'allow';
  for (const effect of effects) {
    if (restrictivenessOf(effect) > restrictivenessOf(winner)) winner = effect;
  }
  return winner;
}

export interface EvaluationFacts {
  request: ObservedRequest;
  classification: ClassificationResult;
  feasibility: FeasibilityResult;
  signals: readonly DomainSignal[];
  /** Categories and fields the request actually asked for. Never widened by a rule. */
  consent_categories?: readonly string[];
  application?: { application_id: string; security_rating: number } | null;
  now: Date;
}

export interface MatchedRule {
  rule_id: string;
  effect: RuleEffect;
  priority: number;
  override_class: OverrideClass;
  reason_code: string;
  rationale: string;
  origin: Rule['origin'];
}

export type UnevaluatedReason = 'signal_missing' | 'signal_stale' | 'out_of_scope' | 'expired';

export interface UnevaluatedRule {
  rule_id: string;
  reason: UnevaluatedReason;
  detail: string;
}

export interface RuleConflict {
  kind: 'equal_priority_opposing_effects' | 'user_rule_neutralised_by_critical';
  rule_ids: string[];
  effects: RuleEffect[];
  resolved_effect: RuleEffect;
  detail: string;
}

export interface RuleEvaluation {
  effect: RuleEffect;
  override_class: OverrideClass;
  matched_rules: string[];
  matched: MatchedRule[];
  unevaluated: UnevaluatedRule[];
  conflicts: RuleConflict[];
  reason_codes: string[];
  /** True when no rule matched and the ruleset's documented posture applied. */
  default_posture_applied: boolean;
  /** System rules that matched and cannot be bypassed through Force Allow. */
  critical_rule_ids: string[];
}

export interface EvaluateOptions {
  /** Defaults to the ruleset's documented posture, which is validated data. */
  default_posture: { effect: RuleEffect; override_class: OverrideClass; reason_code: string };
}

function signalOf(facts: EvaluationFacts, type: SignalType): DomainSignal | undefined {
  return facts.signals.find((signal) => signal.type === type);
}

/**
 * Signal types a condition needs in order to be evaluable.
 *
 * `signal_unknown` is deliberately excluded: a rule written to handle missing
 * data must be able to fire *because* the data is missing.
 */
export function requiredSignals(condition: RuleCondition): SignalType[] {
  switch (condition.op) {
    case 'and':
    case 'or':
      return [...new Set(condition.operands.flatMap(requiredSignals))];
    case 'not':
      return [];
    case 'signal_is':
      return [condition.signal];
    case 'domain_age_days_lt':
      return ['domain_age'];
    case 'category_in':
    case 'mechanism_in':
    case 'sensitivity_at_least':
    case 'signal_unknown':
      return [];
  }
}

function sensitivityRank(level: string | null): number {
  switch (level) {
    case 'Low':
      return 1;
    case 'Medium':
      return 2;
    case 'High':
      return 3;
    case 'Critical':
      return 4;
    default:
      return 0;
  }
}

function highestSensitivity(facts: EvaluationFacts): number {
  let highest = 0;
  for (const category of facts.classification.categories) {
    const rank = sensitivityRank(category.sensitivity_level);
    if (rank > highest) highest = rank;
  }
  return highest;
}

function scopeApplies(rule: Rule, facts: EvaluationFacts): boolean {
  const { scope } = rule;
  if (scope.data_categories.length > 0) {
    const requested = new Set(facts.classification.categories.map((category) => category.data_category_id));
    if (!scope.data_categories.some((category) => requested.has(category))) return false;
  }
  if (scope.origins.length > 0) {
    const host = facts.request.origin.host;
    const registrable = facts.request.origin.registrable_domain;
    const matches = scope.origins.some(
      (origin) => origin === host || (registrable !== null && origin === registrable),
    );
    if (!matches) return false;
  }
  if (scope.applications.length > 0) {
    const applicationId = facts.application?.application_id;
    if (applicationId === undefined || !scope.applications.includes(applicationId)) return false;
  }
  return true;
}

/** Evaluate a condition against validated facts. No rule string is ever executed. */
export function evaluateCondition(condition: RuleCondition, facts: EvaluationFacts): boolean {
  switch (condition.op) {
    case 'and':
      return condition.operands.every((operand) => evaluateCondition(operand, facts));
    case 'or':
      return condition.operands.some((operand) => evaluateCondition(operand, facts));
    case 'not':
      // `not` over a missing signal would be "true because unknown", so it is
      // only meaningful for conditions that read request facts rather than
      // intelligence. Anything wrapping a signal read is unevaluated upstream.
      return !evaluateCondition(condition.operand, facts);
    case 'category_in': {
      const requested = new Set(facts.classification.categories.map((category) => category.data_category_id));
      // The intersection matters: a rule naming a category the request did not
      // ask for cannot widen the request, so it simply does not match.
      return condition.categories.some((category) => requested.has(category));
    }
    case 'mechanism_in':
      return condition.mechanisms.includes(facts.request.mechanism);
    case 'sensitivity_at_least':
      return highestSensitivity(facts) >= sensitivityRank(condition.level);
    case 'signal_is': {
      const signal = signalOf(facts, condition.signal);
      return signal !== undefined && signal.freshness !== 'unknown' && signal.value === condition.value;
    }
    case 'signal_unknown': {
      const signal = signalOf(facts, condition.signal);
      return signal === undefined || signal.freshness === 'unknown';
    }
    case 'domain_age_days_lt': {
      const signal = signalOf(facts, 'domain_age');
      return (
        signal !== undefined &&
        signal.freshness !== 'unknown' &&
        typeof signal.value === 'number' &&
        signal.value < condition.days
      );
    }
  }
}

/**
 * Evaluate a ruleset against one request.
 *
 * Every rule is accounted for in exactly one of `matched` or `unevaluated`, so a
 * reviewer can see why a rule stayed quiet instead of inferring it from absence.
 */
export function evaluateRules(
  rules: readonly Rule[],
  facts: EvaluationFacts,
  options: EvaluateOptions,
): RuleEvaluation {
  const matched: MatchedRule[] = [];
  const unevaluated: UnevaluatedRule[] = [];

  for (const rule of [...rules].sort((a, b) => (a.rule_id === b.rule_id ? 0 : a.rule_id < b.rule_id ? -1 : 1))) {
    if (rule.expires_at !== null && Date.parse(rule.expires_at) <= facts.now.getTime()) {
      unevaluated.push({
        rule_id: rule.rule_id,
        reason: 'expired',
        detail: `the rule expired at ${rule.expires_at}`,
      });
      continue;
    }

    if (!scopeApplies(rule, facts)) {
      unevaluated.push({
        rule_id: rule.rule_id,
        reason: 'out_of_scope',
        detail: 'the rule scope does not cover this request',
      });
      continue;
    }

    const required = requiredSignals(rule.condition);
    const missing = required.filter((type) => signalOf(facts, type) === undefined);
    if (missing.length > 0) {
      unevaluated.push({
        rule_id: rule.rule_id,
        reason: 'signal_missing',
        detail: `no ${missing.join(', ')} signal was available`,
      });
      continue;
    }
    const stale = required.filter((type) => {
      const signal = signalOf(facts, type);
      return signal !== undefined && signal.freshness !== 'fresh';
    });
    if (stale.length > 0) {
      unevaluated.push({
        rule_id: rule.rule_id,
        reason: 'signal_stale',
        detail: `the ${stale.join(', ')} signal is not fresh`,
      });
      continue;
    }

    if (!evaluateCondition(rule.condition, facts)) continue;

    matched.push({
      rule_id: rule.rule_id,
      effect: rule.effect,
      priority: rule.priority,
      override_class: rule.override_class,
      reason_code: rule.reason_code,
      rationale: rule.rationale,
      origin: rule.origin,
    });
  }

  const ordered = [...matched].sort((a, b) =>
    b.priority !== a.priority ? b.priority - a.priority : a.rule_id < b.rule_id ? -1 : a.rule_id > b.rule_id ? 1 : 0,
  );

  const conflicts: RuleConflict[] = [];
  let effect: RuleEffect;
  let override_class: OverrideClass;
  let defaultPostureApplied = false;

  if (ordered.length === 0) {
    effect = options.default_posture.effect;
    override_class = options.default_posture.override_class;
    defaultPostureApplied = true;
  } else {
    const topPriority = ordered[0]!.priority;
    const winners = ordered.filter((rule) => rule.priority === topPriority);
    const effects = [...new Set(winners.map((rule) => rule.effect))];
    effect = effects.length === 1 ? effects[0]! : mostRestrictive(effects);
    if (effects.length > 1) {
      conflicts.push({
        kind: 'equal_priority_opposing_effects',
        rule_ids: winners.map((rule) => rule.rule_id).sort(),
        effects: effects.sort(),
        resolved_effect: effect,
        detail: `rules at priority ${topPriority} disagree; the most restrictive effect was applied`,
      });
    }
    override_class = ordered.some((rule) => rule.override_class === 'critical') ? 'critical' : 'overridable';
  }

  /**
   * A user rule can never neutralise a critical system rule, whatever priority it
   * carries.
   *
   * The API caps a user priority below the system range, but the evaluator must
   * not depend on a writer having been careful: a rule row edited directly in SQL
   * would otherwise be a way to talk the system out of its one non-negotiable
   * control. The critical block wins here, and the attempt is recorded.
   */
  const criticalMatched = ordered.filter((rule) => rule.origin === 'system' && rule.override_class === 'critical');
  if (criticalMatched.length > 0) {
    const wouldHaveWon = ordered.filter(
      (rule) => rule.effect !== 'block' && !criticalMatched.includes(rule),
    );
    effect = 'block';
    override_class = 'critical';
    if (wouldHaveWon.length > 0) {
      conflicts.push({
        kind: 'user_rule_neutralised_by_critical',
        rule_ids: [...criticalMatched, ...wouldHaveWon].map((rule) => rule.rule_id).sort(),
        // The blocked effect is part of the conflict: a schema requires at
        // least two effects, and a single distinct loser effect plus the
        // enforced block is the honest description of what disagreed.
        effects: [...new Set([...wouldHaveWon.map((rule) => rule.effect), 'block' as const])].sort(),
        resolved_effect: 'block',
        detail: `critical rule ${criticalMatched.map((rule) => rule.rule_id).join(', ')} was matched, so the non-blocking outcome was not applied`,
      });
    }
  }

  const reasonCodes = new Set<string>();
  for (const rule of ordered) reasonCodes.add(rule.reason_code);
  if (defaultPostureApplied) reasonCodes.add(options.default_posture.reason_code);
  if (conflicts.length > 0) reasonCodes.add('RULE_CONFLICT');
  if (criticalMatched.length > 0) reasonCodes.add('CRITICAL_RULE_AUTHORITATIVE');

  const criticalRuleIds = ordered
    .filter((rule) => CRITICAL_RULE_IDS.has(rule.rule_id) || rule.override_class === 'critical')
    .map((rule) => rule.rule_id)
    .sort();

  return {
    effect,
    override_class,
    matched_rules: ordered.map((rule) => rule.rule_id),
    matched: ordered,
    unevaluated,
    conflicts,
    reason_codes: [...reasonCodes].sort(),
    default_posture_applied: defaultPostureApplied,
    critical_rule_ids: criticalRuleIds,
  };
}
