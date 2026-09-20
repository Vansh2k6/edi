/**
 * Network block rule lifecycle (`declarativeNetRequest`).
 *
 * Bug-hunt fix: block rules used to be installed with `removeRuleIds: []` and
 * nothing ever removed them, so a blocked host stayed network-blocked for every
 * origin the extension can access until the browser restarted — even after the
 * policy changed or the owner Force Allowed the page. Rules also keyed off the
 * request id, which a later decision for the same host can never name.
 *
 * The rule id is therefore derived deterministically from the *host*:
 *  - one rule per host, so a later decision for that host lifts the block by
 *    recomputing the same id,
 *  - a re-block passes the id in `removeRuleIds`, replacing instead of
 *    accumulating duplicates,
 *  - removal needs no stored state that could be lost when the MV3 service
 *    worker is suspended,
 *  - the id spans the dynamic-rule range, not an 8000-slot space where a
 *    couple of dozen blocks would start colliding.
 */

const BLOCK_RULE_ID_BASE = 1000;

/** The slice of the Chrome API the lifecycle needs; fakes satisfy this in tests. */
export interface DynamicRulesApi {
  updateDynamicRules(options: chrome.declarativeNetRequest.UpdateRuleOptions): Promise<void>;
}

export function blockRuleIdFor(host: string): number {
  // Keep the id within the positive int32 dynamic-rule range even for the most
  // negative hash, while still spanning ~2^31 slots.
  return BLOCK_RULE_ID_BASE + (Math.abs(hash(host)) % 2147482647);
}

function hash(value: string): number {
  let result = 0;
  for (let index = 0; index < value.length; index += 1) {
    result = (result << 5) - result + value.charCodeAt(index);
    result |= 0;
  }
  return result;
}

/**
 * Install (or replace) the network block for a host. Returns whether the rule
 * was actually applied — an unapplied block must never be attested as enforced.
 */
export async function installBlockRule(api: DynamicRulesApi, host: string): Promise<boolean> {
  const id = blockRuleIdFor(host);
  try {
    await api.updateDynamicRules({
      addRules: [
        {
          id,
          priority: 1,
          action: { type: 'block' as chrome.declarativeNetRequest.RuleActionType },
          condition: { urlFilter: `||${host}`, resourceTypes: ['xmlhttprequest' as chrome.declarativeNetRequest.ResourceType] },
        },
      ],
      // Replacing by the same id keeps one rule per host even when decisions
      // for the host arrive repeatedly.
      removeRuleIds: [id],
    });
    return true;
  } catch {
    return false;
  }
}

/**
 * Lift the network block for a host. Removing an id that is not installed is a
 * clean no-op in the Chrome API, so "allow a host that was never blocked" is
 * not an error.
 */
export async function releaseBlockRule(api: DynamicRulesApi, host: string): Promise<boolean> {
  try {
    await api.updateDynamicRules({ removeRuleIds: [blockRuleIdFor(host)] });
    return true;
  } catch {
    return false;
  }
}
