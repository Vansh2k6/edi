import {
  riskAssessmentSchema,
  riskCategoryForScore,
  type RiskAssessment,
  type RiskFactor,
  type RiskInput,
  type RiskUncertainty,
  type SensitivityLevel,
} from '@pv/schemas';
import {
  BAND_RECOMMENDATIONS,
  applicationSeverity,
  ageSeverity,
  contributionOf,
  findSignal,
  mechanismSeverity,
  reputationSeverity,
  scopeSeverity,
  sensitivitySeverity,
  signalIsUsable,
  toFactor,
  UNKNOWN_SEVERITY,
} from './factors.js';
import { deterministicIntelligence, type RiskIntelligence } from './intelligence.js';

/**
 * Deterministic, explainable scoring (`T024`, W6.1).
 *
 * Every factor is recorded with its weight, its input and whether the input was
 * available. Two properties matter more than the exact numbers:
 *
 * - a missing or stale input raises uncertainty and contributes the documented
 *   non-zero floor, so an outage can never lower a score;
 * - the advisory model can raise the score but cannot lower it, and is recorded
 *   with its identifier and version (`D-007`, `D-017`).
 */
export function assessRisk(input: RiskInput, intelligence: RiskIntelligence = deterministicIntelligence): RiskAssessment {
  const factors: RiskFactor[] = [];
  let uncertainty: RiskUncertainty = 'none';
  const raise = (level: RiskUncertainty): void => {
    if (level === 'high' || (level === 'elevated' && uncertainty === 'none')) uncertainty = level;
  };

  const sensitivityLevels = input.data_categories
    .map((category) => category.sensitivity_level)
    .filter((level): level is SensitivityLevel => level !== null);
  const registryMissing = input.data_categories.length - sensitivityLevels.length;

  if (input.classification_unknown || input.data_categories.length === 0) {
    factors.push(
      toFactor({
        label: 'data_sensitivity',
        value: null,
        detail:
          'no data category could be established, so sensitivity is unknown and is scored at the unknown floor rather than at zero',
        severity: UNKNOWN_SEVERITY,
        input_unknown: true,
      }),
    );
    raise('high');
  } else if (registryMissing > 0) {
    factors.push(
      toFactor({
        label: 'data_sensitivity',
        value: [...sensitivityLevels].sort().join(', ') || null,
        detail: `${registryMissing} categor${registryMissing === 1 ? 'y has' : 'ies have'} no registered sensitivity level; scored at the unknown floor`,
        severity: UNKNOWN_SEVERITY,
        input_unknown: true,
      }),
    );
    raise('elevated');
  } else {
    const highest = [...sensitivityLevels].sort(
      (a, b) => sensitivitySeverity(b) - sensitivitySeverity(a),
    )[0]!;
    factors.push(
      toFactor({
        label: 'data_sensitivity',
        value: highest,
        detail: `highest classification is ${highest} sensitivity across ${input.data_categories.length} categor${
          input.data_categories.length === 1 ? 'y' : 'ies'
        }`,
        severity: sensitivitySeverity(highest),
      }),
    );
  }

  factors.push(
    toFactor({
      label: 'scope_breadth',
      value: input.data_categories.length + input.requested_field_count,
      detail: `${input.data_categories.length} categor${
        input.data_categories.length === 1 ? 'y' : 'ies'
      } and ${input.requested_field_count} requested field${input.requested_field_count === 1 ? '' : 's'}`,
      severity: scopeSeverity(input.data_categories.length, input.requested_field_count),
    }),
  );

  const reputation = findSignal(input.signals, 'reputation');
  if (reputation === undefined || !signalIsUsable(reputation)) {
    factors.push(
      toFactor({
        label: 'domain_reputation',
        value: null,
        detail:
          reputation === undefined
            ? 'no reputation signal was available; scored at the unknown floor, never at zero'
            : `the reputation signal is ${reputation.freshness}: ${reputation.unknown_reason ?? 'no reason recorded'}`,
        severity: UNKNOWN_SEVERITY,
        input_unknown: true,
      }),
    );
    raise('elevated');
  } else {
    factors.push(
      toFactor({
        label: 'domain_reputation',
        value: typeof reputation.value === 'string' ? reputation.value : String(reputation.value),
        detail: `reputation ${String(reputation.value)} from ${reputation.source} (confidence ${reputation.confidence})`,
        severity: reputationSeverity(reputation.value),
      }),
    );
  }

  const age = findSignal(input.signals, 'domain_age');
  if (age === undefined || !signalIsUsable(age) || typeof age.value !== 'number') {
    factors.push(
      toFactor({
        label: 'domain_age',
        value: typeof age?.value === 'number' ? age.value : null,
        detail:
          age === undefined
            ? 'the domain age could not be established; a young domain is not assumed and an old one is not assumed either'
            : `the domain age signal is ${age.freshness}`,
        severity: UNKNOWN_SEVERITY,
        input_unknown: true,
      }),
    );
    raise('elevated');
  } else {
    factors.push(
      toFactor({
        label: 'domain_age',
        value: age.value,
        detail: `the domain is ${age.value} days old`,
        severity: ageSeverity(age.value),
      }),
    );
  }

  factors.push(
    toFactor({
      label: 'mechanism',
      value: input.mechanism,
      detail:
        input.mechanism === 'unsupported'
          ? 'the extension cannot inspect or enforce this mechanism'
          : `a ${input.mechanism} request over ${input.feasibility} feasibility`,
      severity: mechanismSeverity(input.mechanism),
    }),
  );

  if (input.feasibility === 'indeterminate') {
    raise('elevated');
  }

  if (input.application !== null) {
    factors.push(
      toFactor({
        label: 'application_trust',
        value: input.application.security_rating,
        detail: `application ${input.application.application_id} has security rating ${input.application.security_rating}`,
        severity: applicationSeverity(input.application.security_rating),
      }),
    );
  }

  if (input.default_posture_applied) {
    raise('elevated');
  }

  // Synchronous by design: the decision path must not wait on a model.
  const advisory = intelligence.advisoryFor(input);
  const deterministicScore = clampScore(factors.reduce((total, factor) => total + contributionOf(factor), 0));

  let score = deterministicScore;
  let model: RiskAssessment['model'] = null;
  let source: RiskAssessment['source'] = 'deterministic';

  if (advisory !== null && advisory.score > deterministicScore) {
    // Advisory input may only raise the score. A model that "improves" a score by
    // lowering it would be a way to talk the system out of a control.
    score = clampScore(advisory.score);
    model = advisory.model;
    source = 'model_advisory';
    factors.push({
      label: 'model_advisory',
      weight: 0,
      value: advisory.score,
      detail: `advisory model ${advisory.model.model_id}@${advisory.model.version} scored ${advisory.score}, above the deterministic ${deterministicScore}`,
      input_unknown: false,
    });
  }

  const category = riskCategoryForScore(score);

  return riskAssessmentSchema.parse({
    risk_score: score,
    risk_category: category,
    recommendation: BAND_RECOMMENDATIONS[category] ?? BAND_RECOMMENDATIONS.Medium,
    factors,
    uncertainty,
    model,
    source,
  });
}

function clampScore(score: number): number {
  if (Number.isNaN(score)) return 0;
  return Math.max(0, Math.min(100, Math.round(score)));
}
