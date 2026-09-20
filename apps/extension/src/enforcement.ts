import { enforcementAttestationSchema, type EnforcementAttestation, type Mechanism } from '@pv/schemas';

/**
 * Enforcement planning and attestation (`W7.4`, `W7.5`, `T031`).
 *
 * The extension says what the platform could actually do: a network-level rule
 * exists for fetch and XHR; the other mechanisms cannot be prevented here, and
 * pretending otherwise would turn a warning into a false claim of protection
 * (D-025). Only an attested block is recorded as enforced, so the audit trail
 * never overstates the protection the browser provided.
 */

export interface EnforcementPlan {
  enforceable: boolean;
  /** Named only when enforceable is false; `platform` means the browser cannot prevent it. */
  reason: string | null;
}

/**
 * Whether a BLOCK decision can be enforced for this mechanism.
 *
 * `declarativeNetRequest` matches network requests; fetch and XHR are network
 * requests the platform can prevent. Beacons ride the same network layer but
 * are fire-and-forget, forms navigate the document, and websockets upgrade a
 * connection — a static rule either does not see them in time or cannot stop
 * the page's own navigation, so the honest answer is a warning, not a block.
 */
export function planEnforcement(decision: 'ALLOW' | 'WARN' | 'BLOCK' | 'ASK_USER', mechanism: Mechanism): EnforcementPlan {
  if (decision !== 'BLOCK') return { enforceable: true, reason: null };
  if (mechanism === 'fetch' || mechanism === 'xhr') return { enforceable: true, reason: null };
  return {
    enforceable: false,
    reason: `a ${mechanism} request cannot be prevented at the network level; the decision is surfaced as a warning, not an enforced block`,
  };
}

/**
 * The attestation record for one enforcement attempt (W7.5).
 *
 * `ruleId` is the decision's blocking rule when the block came from a specific
 * rule. Non-block decisions produce no attestation at all — there is nothing
 * to attest. The return value parses against the shipped schema, so the core
 * can store it verbatim.
 */
export function buildEnforcementAttestation(
  enforced: boolean,
  mechanism: Mechanism,
  ruleId: string | null,
  decision: 'ALLOW' | 'WARN' | 'BLOCK' | 'ASK_USER' = 'BLOCK',
): EnforcementAttestation | null {
  if (decision !== 'BLOCK') return null;
  const plan = planEnforcement(decision, mechanism);
  const attestation: EnforcementAttestation = {
    enforced: enforced && plan.enforceable,
    mechanism,
    at: new Date().toISOString(),
    rule_id: ruleId,
    not_enforced_reason: plan.enforceable ? null : plan.reason,
  };
  const parsed = enforcementAttestationSchema.safeParse(attestation);
  if (!parsed.success) return null;
  return parsed.data;
}
