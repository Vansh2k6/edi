import type { DataCategory, ObservedRequest } from '@pv/schemas';
import {
  CLASSIFICATION_MAPPINGS,
  type ClassificationMapping,
  type EvidenceSource,
  type EvidenceStrength,
} from './registry.js';

export interface Evidence {
  mapping_id: string;
  data_category_id: string;
  strength: EvidenceStrength;
  source: EvidenceSource;
  /** The field name or the path fragment that matched. */
  matched_on: string;
}

export interface ClassifiedCategory {
  data_category_id: string;
  rationale: string;
  confidence: 'high' | 'low';
  mapping_ids: string[];
  /** Category sensitivity when the registry knows it. */
  sensitivity_level: DataCategory['sensitivity_level'] | null;
}

export interface ClassificationConflict {
  kind: 'ambiguous_field' | 'unsupported_mechanism_with_fields';
  detail: string;
  category_ids: string[];
  matched_on: string | null;
}

export interface ClassificationResult {
  categories: ClassifiedCategory[];
  evidence: Evidence[];
  conflicts: ClassificationConflict[];
  unknown: boolean;
  unknown_reason: string | null;
  /** Nothing is decided here; this only reports what was inferred. */
  decided: false;
}

function destinationPath(destination: string): string {
  try {
    return new URL(destination).pathname.toLowerCase();
  } catch {
    // A destination we cannot parse is still compared as a raw fragment rather
    // than silently ignored: absence of parsing is not absence of evidence.
    return destination.toLowerCase();
  }
}

function matchField(field: string, mapping: ClassificationMapping): boolean {
  const name = field.toLowerCase();
  return mapping.field_patterns.some((pattern) =>
    mapping.strength === 'strong' ? name === pattern : name.includes(pattern),
  );
}

function matchPath(path: string, mapping: ClassificationMapping): string | null {
  return mapping.path_patterns.find((pattern) => path.includes(pattern)) ?? null;
}

/**
 * Classify the data categories a request involves (`T011`).
 *
 * Deterministic: same request, same registry, same output. A request with no
 * matching evidence is `unknown` with a reason - never a default-low guess.
 */
export function classifyRequest(
  request: ObservedRequest,
  categories: readonly DataCategory[],
  mappings: readonly ClassificationMapping[] = CLASSIFICATION_MAPPINGS,
): ClassificationResult {
  const path = destinationPath(request.destination);
  const evidence: Evidence[] = [];

  for (const field of request.requested_data) {
    for (const mapping of mappings) {
      if (matchField(field, mapping)) {
        evidence.push({
          mapping_id: mapping.mapping_id,
          data_category_id: mapping.data_category_id,
          strength: mapping.strength,
          source: 'field',
          matched_on: field,
        });
      }
    }
  }

  for (const mapping of mappings) {
    const matched = matchPath(path, mapping);
    if (matched !== null) {
      evidence.push({
        mapping_id: mapping.mapping_id,
        data_category_id: mapping.data_category_id,
        strength: mapping.strength,
        source: 'path',
        matched_on: matched,
      });
    }
  }

  const byCategory = new Map<string, Evidence[]>();
  for (const item of evidence) {
    const list = byCategory.get(item.data_category_id) ?? [];
    list.push(item);
    byCategory.set(item.data_category_id, list);
  }

  const categoriesOut: ClassifiedCategory[] = [];
  for (const [categoryId, items] of [...byCategory.entries()].sort(([a], [b]) => a.localeCompare(b))) {
    const hasStrong = items.some((item) => item.strength === 'strong');
    const registryEntry = categories.find((category) => category.data_category_id === categoryId);
    const mappingIds = [...new Set(items.map((item) => item.mapping_id))].sort();
    const matchedOn = [...new Set(items.map((item) => `${item.source}:${item.matched_on}`))].sort();
    categoriesOut.push({
      data_category_id: categoryId,
      rationale: `${hasStrong ? 'strong' : 'weak'} evidence from ${mappingIds.join(', ')} (${matchedOn.join(', ')})`,
      confidence: hasStrong ? 'high' : 'low',
      mapping_ids: mappingIds,
      sensitivity_level: registryEntry?.sensitivity_level ?? null,
    });
  }

  const conflicts: ClassificationConflict[] = [];

  // A single field claimed by two categories is genuine ambiguity, not a
  // multi-category request, and must be surfaced rather than resolved silently.
  const strongFieldClaims = new Map<string, Set<string>>();
  for (const item of evidence) {
    if (item.source !== 'field' || item.strength !== 'strong') continue;
    const claims = strongFieldClaims.get(item.matched_on) ?? new Set<string>();
    claims.add(item.data_category_id);
    strongFieldClaims.set(item.matched_on, claims);
  }
  for (const [field, claims] of strongFieldClaims) {
    if (claims.size > 1) {
      conflicts.push({
        kind: 'ambiguous_field',
        detail: `field "${field}" maps to multiple categories with equal specificity`,
        category_ids: [...claims].sort(),
        matched_on: field,
      });
    }
  }

  if (request.mechanism === 'unsupported' && request.requested_data.length > 0) {
    conflicts.push({
      kind: 'unsupported_mechanism_with_fields',
      detail: 'the observed mechanism is unsupported but the request carries data fields',
      category_ids: categoriesOut.map((category) => category.data_category_id),
      matched_on: null,
    });
  }

  const unknown = evidence.length === 0;
  return {
    categories: categoriesOut,
    evidence,
    conflicts,
    unknown,
    unknown_reason: unknown
      ? request.requested_data.length === 0
        ? 'the request carried no data fields to classify'
        : 'no classification mapping matched the observed fields or path'
      : null,
    decided: false,
  };
}
