import {
  decisionSchema,
  type Decision,
  type DecisionOutcome,
  type ObservedRequest,
  type RiskAssessment,
  type Consent,
  type DomainSignal,
} from '@pv/schemas';
import type { ClassificationResult } from './classify.js';
import type { FeasibilityResult } from './feasibility.js';
import type { RuleEvaluation } from './evaluate.js';

/**
 * Decision engine (`T025`, W6.3).
 *
 * The deterministic rules remain authoritative (`D-009`); the risk assessment
 * escalates, never de-escalates. That ordering is the whole reason a model can
 * never be allowed to decide anything on its own: risk can tighten a control, and
 * only policy can loosen one.
 *
 * A critical block is reported structurally (`critical_security_block`,
 * `overridable: false`) rather than by matching a string in `reason_codes`, so
 * Force Allow cannot be built on a string comparison that a renamed code defeats.
 */

export interface DecideInput {
  request: ObservedRequest;
  classification: ClassificationResult;
  feasibility: FeasibilityResult;
  signals: readonly DomainSignal[];
  rules: RuleEvaluation;
  risk: RiskAssessment;
  consent?: readonly Consent[];
  /** `ruleset_version` + the user policy version, recorded for reproducibility. */
  policy_version: string;
  now: Date;
  decision_id: string;
}

export interface DecisionDraft {
  decision: DecisionOutcome;
  reason_codes: string[];
  escalations: string[];
}

/**
 * Turn rule output and risk into one outcome.
 *
 * Escalation ladder, and nothing else:
 * - a critical block stays a block, whatever the risk says;
 * - a policy block stays a block;
 * - anything else escalates by risk band and by uncertainty.
 */
// Merges deterministic rule effects with risk bands to calculate final decision outcome and escalation codes
export function combineRulesAndRisk(input: {
  rule_effect: RuleEvaluation['effect'];
  override_class: RuleEvaluation['override_class'];
  risk: RiskAssessment;
  classification_unknown: boolean;
}): DecisionDraft {
  const reasonCodes = new Set<string>();
  const escalations: string[] = [];

  // Deterministic policy blocks are absolute and cannot be downgraded by low risk
  if (input.rule_effect === 'block') {
    return {
      decision: 'BLOCK',
      reason_codes: [...reasonCodes],
      escalations,
    };
  }

  // Initial baseline decision established by the deterministic policy evaluation
  let decision: DecisionOutcome =
    input.rule_effect === 'allow' ? 'ALLOW' : input.rule_effect === 'warn' ? 'WARN' : 'ASK_USER';

  // Helper to escalate a decision to a stricter outcome when risk or uncertainty exceeds thresholds
  const escalateTo = (next: DecisionOutcome, code: string, detail: string): void => {
    const rank = { ALLOW: 0, WARN: 1, ASK_USER: 2, BLOCK: 3 } satisfies Record<DecisionOutcome, number>;
    if (rank[next] > rank[decision]) {
      decision = next;
      reasonCodes.add(code);
      escalations.push(detail);
    } else if (rank[next] === rank[decision] && rank[next] > 0) {
      // Same-band escalation: the outcome does not change but the cause still
      // matters. Dropping the code here made a warn-rule-plus-High-band
      // decision indistinguishable from a plain rule warn.
      reasonCodes.add(code);
      escalations.push(detail);
    }
  };

  // Critical risk score escalates any non-block decision to prompt the user
  if (input.risk.risk_category === 'Critical') {
    escalateTo('ASK_USER', 'RISK_CRITICAL_ESCALATION', `risk band Critical (${input.risk.risk_score})`);
  } else if (input.risk.risk_category === 'High') {
    // High risk score escalates allow decisions to warning status
    escalateTo('WARN', 'RISK_HIGH_ESCALATION', `risk band High (${input.risk.risk_score})`);
  }

  // High uncertainty in intelligence data safely escalates to user verification
  if (input.risk.uncertainty === 'high') {
    escalateTo(
      'ASK_USER',
      'UNKNOWN_INPUT_ESCALATION',
      'key inputs were unavailable, so the request is surfaced rather than decided',
    );
  }

  // Requests with unknown data categories require explicit user confirmation
  if (input.classification_unknown) {
    escalateTo('ASK_USER', 'CLASSIFICATION_UNKNOWN_ESCALATION', 'no data category could be established');
  }

  return { decision, reason_codes: [...reasonCodes].sort(), escalations };
}

// Builds the human-readable explanation and audit trail describing why a decision was reached
export function buildExplanation(input: DecideInput): Decision['explanation'] {
  const why: string[] = [];
  const highest = [...input.classification.categories]
    .sort((a, b) => (a.sensitivity_level ?? '').localeCompare(b.sensitivity_level ?? ''))
    .at(-1);
  if (highest !== undefined) {
    why.push(`${highest.data_category_id} data requested (${highest.sensitivity_level ?? 'unregistered'} sensitivity)`);
  }
  why.push(...input.rules.matched.map((rule) => `${rule.rule_id}: ${rule.rationale}`));
  if (input.rules.default_posture_applied) {
    why.push('no rule matched, so the documented default posture applies');
  }
  why.push(...input.risk.factors.filter((factor) => factor.input_unknown).map((factor) => `${factor.label} unavailable: ${factor.detail}`));
  why.push(...input.feasibility.reasons);

  // Return structured explanation object conforming to audit specifications
  return {
    website: input.request.origin.display,
    origin: input.request.origin,
    requested_data: [...input.request.requested_data],
    why: [...new Set(why)].slice(0, 16),
    domain_signals: [...input.signals],
    matched_rules: [...input.rules.matched_rules],
    policy_version: input.policy_version,
    overridden: false,
  };
}

/**
 * Produce a complete decision.
 *
 * The result is parsed through the schema before it is returned: a decision that
 * cannot be represented is a bug worth failing on, not a value worth storing.
 */
// Main entrypoint executing the complete decision logic and returning a validated decision record
export function decide(input: DecideInput): Decision {
  const draft = combineRulesAndRisk({
    rule_effect: input.rules.effect,
    override_class: input.rules.override_class,
    risk: input.risk,
    classification_unknown: input.classification.unknown,
  });

  const critical = draft.decision === 'BLOCK' && input.rules.override_class === 'critical';
  const reasonCodes = new Set<string>([...input.rules.reason_codes, ...draft.reason_codes]);
  if (critical) reasonCodes.add('CRITICAL_SECURITY_BLOCK');
  if (reasonCodes.size === 0) reasonCodes.add('NO_RULE_MATCHED');

  const explanation = buildExplanation(input);
  explanation.why.push(...draft.escalations);

  return decisionSchema.parse({
    decision_id: input.decision_id,
    request_id: input.request.request_id,
    decision: draft.decision,
    risk_score: input.risk.risk_score,
    risk_level: input.risk.risk_category,
    risk_factors: input.risk.factors,
    reason_codes: [...reasonCodes].sort(),
    matched_rules: [...input.rules.matched_rules],
    // W6.4: the decision carries the categories it judged, so the audit trail
    // can name them without re-deriving classification.
    classified_categories: input.classification.categories.map((category) => category.data_category_id),
    override_class: input.rules.override_class,
    // Derived, never supplied by a caller: only a critical block is unoverridable.
    overridable: !critical && input.rules.override_class !== 'critical',
    policy_version: input.policy_version,
    uncertainty: input.risk.uncertainty,
    conflicts: [...input.rules.conflicts],
    unevaluated_rules: [...input.rules.unevaluated],
    explanation,
    critical_security_block: critical,
    created_at: input.now.toISOString(),
  });
}

/** Whether a decision may be force-allowed. Used by the core, never by a client. */
export function isOverridable(decision: Decision): boolean {
  return decision.overridable && !decision.critical_security_block && decision.override_class === 'overridable';
}
