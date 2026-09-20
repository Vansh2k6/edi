import type { ObservedRequest } from '@pv/schemas';
import type { ClassificationResult } from './classify.js';
import { profileFor } from './feasibility.js';

export interface CategoryMinimization {
  data_category_id: string;
  /** Fields the request asked for that belong to this category. */
  requested_fields: string[];
  /** Fields sufficient to satisfy a minimal request for this category. */
  required_fields: string[];
  /** Requested fields beyond the minimum - candidates for refusal or reduction. */
  excess_fields: string[];
  /** Requested fields this category does not recognise. */
  unknown_fields: string[];
  /** True when the registry has no profile, so no reduction is claimed. */
  profile_missing: boolean;
  /** True when the request asked for nothing at all in this category. */
  empty: boolean;
}

export interface MinimizationResult {
  categories: CategoryMinimization[];
  /** Fields no classified category recognises. */
  unclaimed_fields: string[];
  /** True when more than one sensitivity band appears across the categories. */
  mixed_sensitivity: boolean;
  /** Categories present in the request that this analysis deliberately did not add. */
  scope_expanded: false;
}

/**
 * Determine the minimum data that would satisfy the request (`T013`).
 *
 * This function only ever reports categories the classification already
 * inferred: minimization may reduce scope, never widen it.
 */
export function analyzeMinimization(
  request: ObservedRequest,
  classification: ClassificationResult,
): MinimizationResult {
  const claimed = new Set<string>();
  const categories: CategoryMinimization[] = [];
  const sensitivities = new Set<string>();

  for (const category of classification.categories) {
    const profile = profileFor(category.data_category_id);

    // A requested field belongs to this category when the classification matched
    // it here, or when the category's own vocabulary recognises it. The second
    // case is what makes "excess" meaningful for a field the mapping table did
    // not happen to list (for example postal_address under CAT-CONTACT).
    const evidenceFields = new Set(
      classification.evidence
        .filter((item) => item.data_category_id === category.data_category_id && item.source === 'field')
        .map((item) => item.matched_on.toLowerCase()),
    );
    const knownForCategory = profile ? new Set(profile.known_fields.map((field) => field.toLowerCase())) : null;
    const requestedHere = request.requested_data.filter((field) => {
      const lower = field.toLowerCase();
      if (evidenceFields.has(lower)) return true;
      return knownForCategory !== null && knownForCategory.has(lower);
    });

    if (category.sensitivity_level) sensitivities.add(category.sensitivity_level);
    for (const field of requestedHere) claimed.add(field.toLowerCase());

    if (!profile) {
      categories.push({
        data_category_id: category.data_category_id,
        requested_fields: requestedHere,
        required_fields: requestedHere,
        excess_fields: [],
        unknown_fields: [],
        profile_missing: true,
        empty: requestedHere.length === 0,
      });
      continue;
    }

    const known = new Set(profile.known_fields.map((field) => field.toLowerCase()));
    const minimum = new Set(profile.minimum_fields.map((field) => field.toLowerCase()));
    // Fields the request sent that this category's own mapping claimed but its
    // vocabulary does not define: reported, never dropped silently.
    const unknownFields = requestedHere.filter(
      (field) => evidenceFields.has(field.toLowerCase()) && !known.has(field.toLowerCase()),
    );
    const excessFields = requestedHere.filter((field) => known.has(field.toLowerCase()) && !minimum.has(field.toLowerCase()));

    categories.push({
      data_category_id: category.data_category_id,
      requested_fields: requestedHere,
      required_fields: profile.minimum_fields.filter((field) =>
        requestedHere.some((requested) => requested.toLowerCase() === field.toLowerCase()),
      ),
      excess_fields: excessFields,
      unknown_fields: unknownFields,
      profile_missing: false,
      empty: requestedHere.length === 0,
    });
  }

  const unclaimed = request.requested_data.filter((field) => !claimed.has(field.toLowerCase()));

  return {
    categories,
    unclaimed_fields: unclaimed,
    mixed_sensitivity: sensitivities.size > 1,
    scope_expanded: false,
  };
}
