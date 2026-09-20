import type { DomainSignal, RiskFactor, SensitivityLevel, SignalType } from '@pv/schemas';

/**
 * Named factor weights (W6.1).
 *
 * The weights live in one table so a reviewer can see the whole scoring policy at
 * once and so any score can be reproduced by hand. They are constants rather than
 * fitted values: this is a security control, not a model.
 *
 * The invariant the table serves (`D-008`, `ARCHITECTURE.md` section 9): missing or
 * stale input raises uncertainty and never lowers risk. That is why
 * `UNKNOWN_SEVERITY` is a non-zero floor rather than zero. A zero contribution for
 * "we could not tell" would make provider outages the cheapest way to get a
 * request scored as safe.
 */
export const FACTOR_WEIGHTS = {
  data_sensitivity: 30,
  scope_breadth: 20,
  domain_reputation: 20,
  domain_age: 15,
  mechanism: 10,
  application_trust: 5,
} as const;

export type FactorLabel = keyof typeof FACTOR_WEIGHTS;

/**
 * Severity used when an input is unavailable. It is deliberately mid-high: enough
 * that an outage cannot improve a score, low enough that it is not itself treated
 * as evidence of malice.
 */
export const UNKNOWN_SEVERITY = 0.6;

/** Severity of a sensitivity ladder position, 0 (none/unknown-by-registry) to 1. */
export function sensitivitySeverity(level: SensitivityLevel | null): number {
  switch (level) {
    case 'Low':
      return 0.15;
    case 'Medium':
      return 0.4;
    case 'High':
      return 0.7;
    case 'Critical':
      return 1;
    default:
      return UNKNOWN_SEVERITY;
  }
}

/**
 * How much of the reputation weight a verdict carries. `neutral` is not zero: a
 * domain nobody has reported anything about is not the same as a domain with a
 * good record.
 */
export function reputationSeverity(value: DomainSignal['value']): number {
  switch (value) {
    case 'malicious':
      return 1;
    case 'suspicious':
      return 0.75;
    case 'neutral':
      return 0.4;
    case 'trusted':
      return 0.15;
    default:
      return UNKNOWN_SEVERITY;
  }
}

export function ageSeverity(ageDays: number | null): number {
  if (ageDays === null) return UNKNOWN_SEVERITY;
  if (ageDays < 7) return 1;
  if (ageDays < 30) return 0.85;
  if (ageDays < 180) return 0.6;
  if (ageDays < 730) return 0.4;
  return 0.25;
}

/** A mechanism the extension cannot inspect or enforce carries its own risk. */
export function mechanismSeverity(mechanism: string): number {
  switch (mechanism) {
    case 'unsupported':
      return 1;
    case 'websocket':
      return 0.7;
    case 'beacon':
      return 0.45;
    case 'form':
      return 0.4;
    case 'xhr':
      return 0.3;
    case 'fetch':
      return 0.25;
    default:
      return UNKNOWN_SEVERITY;
  }
}

/** Fewer fields is less exposure; breadth is judged on categories and fields. */
export function scopeSeverity(categoryCount: number, fieldCount: number): number {
  const breadth = categoryCount + Math.max(0, fieldCount - 1) * 0.5;
  if (breadth <= 1) return 0.15;
  if (breadth <= 2) return 0.45;
  if (breadth <= 4) return 0.7;
  return 1;
}

/** 0--100 rating, higher is safer. An unknown rating scores worse than a poor one. */
export function applicationSeverity(rating: number | null): number {
  if (rating === null) return UNKNOWN_SEVERITY;
  return Math.min(1, Math.max(0, 1 - rating / 100));
}

export interface FactorInput {
  label: FactorLabel;
  value: RiskFactor['value'];
  detail: string;
  severity: number;
  input_unknown?: boolean;
}

export function toFactor(input: FactorInput): RiskFactor {
  return {
    label: input.label,
    weight: FACTOR_WEIGHTS[input.label],
    value: input.value,
    detail: input.detail,
    input_unknown: input.input_unknown ?? false,
  };
}

export function contributionOf(factor: RiskFactor): number {
  const severity = severityFor(factor);
  // Weights sum to 100 and severities live in [0, 1], so the weighted sum is
  // already the 0--100 score. The division that used to sit here collapsed
  // every score to 0--1, which no test caught until the scorer got its own
  // suite (T024).
  return factor.weight * severity;
}

/**
 * Recover severity from a recorded factor so a stored assessment can be re-added
 * without keeping a parallel severity table in the record.
 */
function severityFor(factor: RiskFactor): number {
  if (factor.input_unknown) return UNKNOWN_SEVERITY;
  switch (factor.label) {
    case 'data_sensitivity':
      return factor.value === null ? UNKNOWN_SEVERITY : sensitivitySeverity(factor.value as SensitivityLevel);
    case 'scope_breadth':
      return typeof factor.value === 'number' ? scopeSeverity(factor.value, 0) : UNKNOWN_SEVERITY;
    case 'domain_reputation':
      return factor.value === null ? UNKNOWN_SEVERITY : reputationSeverity(factor.value);
    case 'domain_age':
      return ageSeverity(typeof factor.value === 'number' ? factor.value : null);
    case 'mechanism':
      return typeof factor.value === 'string' ? mechanismSeverity(factor.value) : UNKNOWN_SEVERITY;
    case 'application_trust':
      return applicationSeverity(typeof factor.value === 'number' ? factor.value : null);
    default:
      return UNKNOWN_SEVERITY;
  }
}

export function findSignal<T extends SignalType>(
  signals: readonly DomainSignal[],
  type: T,
): DomainSignal | undefined {
  return signals.find((signal) => signal.type === type);
}

/** True when a signal exists and is neither unknown nor stale. */
export function signalIsUsable(signal: DomainSignal | undefined): boolean {
  return signal !== undefined && signal.freshness === 'fresh';
}

export const BAND_RECOMMENDATIONS: Record<string, string> = {
  Low: 'Allow without interrupting the owner; record the decision and the factors behind it.',
  Medium:
    'Allow but surface a warning in the extension overlay so the owner sees what left the browser.',
  High: 'Ask the owner before any data is released; show the factor breakdown and offer a narrowed disclosure.',
  Critical:
    'Do not release data. Show the critical reason first, and note that a critical block cannot be force-allowed.',
};
