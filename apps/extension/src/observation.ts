import {
  observedRequestSchema,
  pageObservationMessageSchema,
  tryNormalizeOrigin,
  type ObservedRequest,
} from '@pv/schemas';

/**
 * Observation normalization (T009, ARCHITECTURE.md boundary 1).
 *
 * The page is untrusted. Everything security-relevant here comes from trusted
 * browser context (the tab's committed URL, the frame relationship, the tab id);
 * the page only contributes the mechanism it used and the field names it sent.
 *
 * Note what is deliberately absent: the page's own origin claim is never copied
 * into the observation, not even as context. It is not merely ignored for the
 * decision, it does not travel at all (D-019 data minimization).
 */

export interface TrustedContext {
  tabUrl: string | null;
  tabId: number | null;
  isTopFrame: boolean;
  redirectChain?: string[];
  now?: Date;
  requestId?: string;
}

export type ObservationRejection =
  | 'malformed_page_message'
  | 'trusted_origin_unavailable'
  | 'trusted_origin_unusable';

export type ObservationResult =
  | { ok: true; request: ObservedRequest }
  | { ok: false; rejection: ObservationRejection; detail: string };

export function buildObservation(message: unknown, context: TrustedContext): ObservationResult {
  const parsedMessage = pageObservationMessageSchema.safeParse(message);
  if (!parsedMessage.success) {
    return {
      ok: false,
      rejection: 'malformed_page_message',
      detail: 'the page message did not match the fixed field set',
    };
  }

  if (context.tabUrl === null || context.tabUrl === '') {
    return {
      ok: false,
      rejection: 'trusted_origin_unavailable',
      detail: 'the tab has no committed URL, so no origin can be attributed',
    };
  }

  const origin = tryNormalizeOrigin(context.tabUrl, {
    topLevelUrl: context.tabUrl,
  });
  if (origin === null) {
    return {
      ok: false,
      rejection: 'trusted_origin_unusable',
      detail: 'the committed URL could not be parsed into an origin',
    };
  }

  // A destination the page did not name cannot be invented; the observed URL is
  // taken as-is and bounded by the schema. The parse must never throw: the
  // values here originate from the untrusted page, and a throwing validation
  // would let a crafted value crash the page's own request. Any contract
  // violation is reported as a rejection instead.
  const candidate = {
    request_id: context.requestId ?? crypto.randomUUID(),
    timestamp: (context.now ?? new Date()).toISOString(),
    origin,
    destination: parsedMessage.data.url,
    requested_data: parsedMessage.data.field_names,
    mechanism: parsedMessage.data.mechanism,
    page_context: {
      top_level_url: context.tabUrl,
      is_top_frame: context.isTopFrame,
    },
    browser_context: {
      tab_id: context.tabId,
      redirect_chain: context.redirectChain ?? [],
    },
  };
  const parsedRequest = observedRequestSchema.safeParse(candidate);
  if (!parsedRequest.success) {
    return {
      ok: false,
      rejection: 'malformed_page_message',
      detail: 'the observed request violated the observation contract',
    };
  }

  return { ok: true, request: parsedRequest.data };
}

/**
 * Record an unsupported mechanism as an explicit observation instead of dropping
 * it (`T009`: an unsupported mechanism must be visible, not silent).
 */
export function observationForUnsupportedMechanism(context: TrustedContext): ObservationResult {
  return buildObservation(
    {
      channel: 'pv-observe',
      mechanism: 'unsupported',
      url: context.tabUrl ?? 'about:blank',
      method: '',
      field_names: [],
      page_claimed_origin: null,
    },
    context,
  );
}
