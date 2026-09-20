import { z } from 'zod';
import { sensitivitySchema } from './vault.js';
import { signalSchema } from './domain-intel.js';
import { mechanismSchema } from './observation.js';

export const riskCategorySchema = z.enum(['Low', 'Medium', 'High', 'Critical']);
export type RiskCategory = z.infer<typeof riskCategorySchema>;

/** One contributing factor, listed so any score can be explained factor by factor. */
export const riskFactorSchema = z.strictObject({
  label: z.string().min(1).max(64),
  weight: z.number().min(0).max(100),
  value: z.union([z.string().max(128), z.number(), z.boolean(), z.null()]),
  detail: z.string().min(1).max(256),
  /** Factors whose input was unavailable are flagged rather than defaulted. */
  input_unknown: z.boolean().default(false),
});
export type RiskFactor = z.infer<typeof riskFactorSchema>;

export const riskUncertaintySchema = z.enum(['none', 'elevated', 'high']);
export type RiskUncertainty = z.infer<typeof riskUncertaintySchema>;

export const riskAssessmentSchema = z.strictObject({
  risk_score: z.number().min(0).max(100),
  risk_category: riskCategorySchema,
  recommendation: z.string().min(1).max(300),
  factors: z.array(riskFactorSchema).min(1).max(24),
  uncertainty: riskUncertaintySchema,
  /** Present only when an advisory model contributed to the score. */
  model: z
    .strictObject({
      model_id: z.string().min(1).max(64),
      version: z.string().min(1).max(32),
      confidence: z.number().min(0).max(1),
    })
    .nullable()
    .default(null),
  /** Which implementation produced the score. Deterministic is authoritative. */
  source: z.enum(['deterministic', 'model_advisory']),
});
export type RiskAssessment = z.infer<typeof riskAssessmentSchema>;

/**
 * Everything the scorer is allowed to consider.
 *
 * Deliberately a flat, validated value rather than live objects: a page cannot
 * reach into the scorer, and an assessment can be recomputed from a stored input
 * exactly as it was computed the first time.
 */
export const riskInputSchema = z.strictObject({
  data_categories: z
    .array(
      z.strictObject({
        data_category_id: z.string().min(1).max(36),
        sensitivity_level: sensitivitySchema.nullable(),
      }),
    )
    .max(120),
  requested_field_count: z.number().int().min(0).max(64),
  mechanism: mechanismSchema,
  feasibility: z.enum(['feasible', 'infeasible', 'indeterminate']),
  signals: z.array(signalSchema).max(32),
  application: z
    .strictObject({
      application_id: z.string().min(1).max(36),
      /** 0--100, higher is safer. */
      security_rating: z.number().min(0).max(100),
    })
    .nullable()
    .default(null),
  /** True when no stored rule matched, so the posture itself is uncertain. */
  default_posture_applied: z.boolean().default(false),
  classification_unknown: z.boolean().default(false),
});
export type RiskInput = z.infer<typeof riskInputSchema>;

export function riskCategoryForScore(score: number): RiskCategory {
  if (score < 25) return 'Low';
  if (score < 50) return 'Medium';
  if (score < 75) return 'High';
  return 'Critical';
}
