import type { Mechanism, ObservedRequest } from '@pv/schemas';
import type { ClassificationResult } from './classify.js';
import { CATEGORY_PROFILES, MECHANISM_CAPABILITIES, type CategoryProfile } from './registry.js';

export type FeasibilityOutcome = 'feasible' | 'infeasible' | 'indeterminate';

export interface FeasibilityResult {
  outcome: FeasibilityOutcome;
  mechanism: Mechanism;
  reasons: string[];
  /** Capabilities the mechanism lacks for the requested categories. */
  missing_capabilities: string[];
  /** Categories whose profile is not in the registry; no claim is made about them. */
  profile_missing: string[];
  /** Reminder carried into every consumer: feasible does not mean permitted. */
  grants_permission: false;
}

export function capabilitiesFor(mechanism: Mechanism): readonly string[] {
  return MECHANISM_CAPABILITIES[mechanism];
}

export function profileFor(categoryId: string): CategoryProfile | undefined {
  return CATEGORY_PROFILES[categoryId];
}

/**
 * Decide whether the observed mechanism could actually yield the classified
 * data (`T012`). Feasibility is about technical possibility; it never grants
 * permission (ARCHITECTURE.md section 5.5).
 */
export function assessFeasibility(
  request: ObservedRequest,
  classification: ClassificationResult,
): FeasibilityResult {
  const capabilities = new Set(capabilitiesFor(request.mechanism));
  const reasons: string[] = [];
  const missing = new Set<string>();
  const profileMissing: string[] = [];

  if (request.mechanism === 'unsupported') {
    return {
      outcome: 'indeterminate',
      mechanism: request.mechanism,
      reasons: ['the request mechanism is not supported, so no capability can be attributed to it'],
      missing_capabilities: [],
      profile_missing: [],
      grants_permission: false,
    };
  }

  if (classification.categories.length === 0) {
    return {
      outcome: 'indeterminate',
      mechanism: request.mechanism,
      reasons: [
        classification.unknown_reason ?? 'no data categories were inferred, so feasibility cannot be assessed',
      ],
      missing_capabilities: [],
      profile_missing: [],
      grants_permission: false,
    };
  }

  for (const category of classification.categories) {
    const profile = profileFor(category.data_category_id);
    if (!profile) {
      profileMissing.push(category.data_category_id);
      reasons.push(`${category.data_category_id} has no capability profile; no feasibility claim is made`);
      continue;
    }
    const satisfiable = profile.any_of.some((capability) => capabilities.has(capability));
    if (!satisfiable) {
      const unavailable = profile.any_of.filter((capability) => !capabilities.has(capability));
      for (const capability of unavailable) missing.add(capability);
      reasons.push(
        `a "${request.mechanism}" request cannot yield ${category.data_category_id} data (needs ${profile.any_of.join(' or ')})`,
      );
    }
  }

  if (profileMissing.length > 0 && missing.size === 0 && profileMissing.length === classification.categories.length) {
    return {
      outcome: 'indeterminate',
      mechanism: request.mechanism,
      reasons,
      missing_capabilities: [],
      profile_missing: profileMissing,
      grants_permission: false,
    };
  }

  if (missing.size > 0) {
    return {
      outcome: 'infeasible',
      mechanism: request.mechanism,
      reasons,
      missing_capabilities: [...missing].sort(),
      profile_missing: profileMissing,
      grants_permission: false,
    };
  }

  if (reasons.length === 0) {
    reasons.push(
      `a "${request.mechanism}" request can yield ${classification.categories
        .map((category) => category.data_category_id)
        .join(', ')} data`,
    );
  }

  return {
    outcome: 'feasible',
    mechanism: request.mechanism,
    reasons,
    missing_capabilities: [],
    profile_missing: profileMissing,
    grants_permission: false,
  };
}
