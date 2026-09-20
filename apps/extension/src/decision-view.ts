import type { Decision } from '@pv/schemas';
import { verdictFor } from '@pv/ui';

/**
 * Overlay view model (PRD.md section 9).
 *
 * The rule this module exists to hold: a critical security block must not present
 * a bypass. `can_force_allow` is derived from the decision - never from what the
 * UI happens to have rendered - so hiding the button is not the only protection.
 */
export interface DecisionView {
  title: string;
  website: string;
  /** Pill tokens from the shared design system (W8.7): the dashboard's verdict for the same decision reads identically. */
  verdict: { tone: string; label: string; background: string; foreground: string };
  requested: string[];
  reasons: string[];
  matched_rules: string[];
  risk_level: Decision['risk_level'];
  risk_score: number;
  can_force_allow: boolean;
  force_allow_label: string | null;
  /** False when the platform could not actually prevent the request. */
  enforceable: boolean;
  enforcement_note: string | null;
  dismissed_automatically: boolean;
}

export interface ViewOptions {
  /** Whether the block was actually enforced, reported by the extension. */
  enforced: boolean;
  mechanism: string;
}

const TITLES: Record<Decision['decision'], string> = {
  BLOCK: 'ACCESS BLOCKED',
  ASK_USER: 'APPROVAL REQUIRED',
  WARN: 'ACCESS WARNING',
  ALLOW: 'ACCESS ALLOWED',
};

export function toDecisionView(decision: Decision, options: ViewOptions): DecisionView {
  const critical = decision.critical_security_block || decision.override_class === 'critical';
  const canForceAllow = decision.overridable && !critical;

  return {
    title: TITLES[decision.decision],
    website: decision.explanation.website,
    verdict: verdictFor(decision.decision),
    requested: decision.explanation.requested_data,
    reasons: decision.explanation.why,
    matched_rules: decision.explanation.matched_rules,
    risk_level: decision.risk_level,
    risk_score: decision.risk_score,
    can_force_allow: canForceAllow,
    force_allow_label: canForceAllow ? 'Force Allow (this decision only)' : null,
    enforceable: options.enforced,
    enforcement_note:
      options.enforced || decision.decision !== 'BLOCK'
        ? null
        : `the platform cannot block a ${options.mechanism} request; this is a warning, not an enforced block`,
    dismissed_automatically: decision.decision === 'ALLOW' && decision.risk_level === 'Low',
  };
}

/** The one-line summary shown in the extension badge tooltip. */
export function badgeSummary(view: DecisionView): string {
  const suffix = view.enforceable ? '' : ' (not enforceable)';
  return `${view.title}: ${view.website}${suffix}`;
}
