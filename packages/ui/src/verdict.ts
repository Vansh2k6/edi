import type { Decision } from '@pv/schemas';

/**
 * Shared verdict tokens (W8.7).
 *
 * One mapping for every surface that shows a decision: the extension overlay
 * and the dashboard must render the same verdict the same way, so the colors
 * and labels live here instead of being re-derived per app. The values are
 * the Status Pills of the committed design system ("The Quiet Institution",
 * `md file/DESIGN.md`) - a redesign updates that document and this module
 * together, never one alone.
 */

export type VerdictTone = 'blocked' | 'approval' | 'warning' | 'allowed';

export interface VerdictTokens {
  tone: VerdictTone;
  label: string;
  /** Pill background (the deep-on-tint pair from the design system). */
  background: string;
  /** Pill text color. */
  foreground: string;
}

const VERDICTS: Record<Decision['decision'], VerdictTokens> = {
  BLOCK: { tone: 'blocked', label: 'ACCESS BLOCKED', background: '#FBEAE8', foreground: '#B3372E' },
  ASK_USER: { tone: 'approval', label: 'APPROVAL REQUIRED', background: '#EAF1FB', foreground: '#1D4ED8' },
  WARN: { tone: 'warning', label: 'ACCESS WARNING', background: '#FBF3E1', foreground: '#9A6B15' },
  ALLOW: { tone: 'allowed', label: 'ACCESS ALLOWED', background: '#E7F5EC', foreground: '#1B7F4B' },
};

/**
 * Tokens for one decision outcome.
 *
 * Fails closed on an unknown outcome: a future decision value rendered with
 * the wrong verdict is worse than a visible error, so callers see the throw
 * instead of a plausible-looking mismatch.
 */
export function verdictFor(outcome: Decision['decision']): VerdictTokens {
  const tokens = VERDICTS[outcome];
  if (tokens === undefined) {
    throw new Error(`unknown decision outcome: ${String(outcome)}`);
  }
  return { ...tokens };
}
