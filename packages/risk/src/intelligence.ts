import type { RiskInput } from '@pv/schemas';

/**
 * Advisory risk intelligence (W6.2, `D-007`, `D-017`).
 *
 * Phase 6 ships the deterministic implementation only (this file); the Phase 11
 * federated model plugs in behind the same interface and stays advisory. Two
 * properties are structural, not policy:
 *
 * - the seam is synchronous and must not do network I/O, because it sits on the
 *   decision path and a slow model would become an availability problem for a
 *   security control;
 * - the score it returns can only raise the deterministic score (enforced in
 *   `assess.ts`), so no model output can talk the system out of a control.
 */

export interface ModelIdentity {
  model_id: string;
  version: string;
  confidence: number;
}

export interface AdvisoryScore {
  score: number;
  model: ModelIdentity;
}

/** A model that has been loaded and health-checked by its owning subsystem. */
export interface AdvisoryModel {
  identity: ModelIdentity;
  score(input: RiskInput): number;
  healthy(): boolean;
}

export interface RiskIntelligence {
  readonly intelligence_id: 'deterministic' | 'model';
  /** `null` when no model contributed to this assessment. */
  advisoryFor(input: RiskInput): AdvisoryScore | null;
}

/**
 * The default: no model, no advisory. A deployment without a model is a supported
 * configuration rather than a degraded one.
 */
export const deterministicIntelligence: RiskIntelligence = {
  intelligence_id: 'deterministic',
  advisoryFor: () => null,
};

export interface ModelIntelligenceOptions {
  /** Below this confidence the advisory is discarded rather than discounted. */
  minimumConfidence: number;
}

/**
 * Wrap a model as advisory intelligence.
 *
 * An unhealthy model, a missing version or an out-of-range score all yield `null`
 * rather than a guess: falling back to the deterministic assessment is always
 * correct, and a broken model silently contributing 0 would be a quiet downgrade.
 */
export function modelAdvisoryIntelligence(
  model: AdvisoryModel | null,
  options: ModelIntelligenceOptions = { minimumConfidence: 0.6 },
): RiskIntelligence {
  if (model === null) return deterministicIntelligence;

  return {
    intelligence_id: 'model',
    advisoryFor: (input) => {
      if (!model.healthy()) return null;
      if (model.identity.version.trim() === '') return null;
      if (model.identity.confidence < options.minimumConfidence) return null;

      let score: number;
      try {
        score = model.score(input);
      } catch {
        // A model that throws must not take the decision path down with it.
        return null;
      }
      if (!Number.isFinite(score) || score < 0 || score > 100) return null;

      return { score: Math.round(score), model: model.identity };
    },
  };
}
