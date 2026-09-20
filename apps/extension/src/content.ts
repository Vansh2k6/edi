import { pageObservationMessageSchema } from '@pv/schemas';
import { buildObservation } from './observation.js';
import { clearOverlay, renderOverlay } from './overlay.js';
import type { DecisionView } from './decision-view.js';

/**
 * Content script (isolated world).
 *
 * Boundary 1 lives here: the page's messages are parsed against a fixed schema and
 * the origin comes from the tab's committed URL, never from the message. The
 * main-world hook is injected from a web-accessible resource, so no remote code
 * is ever loaded.
 */

const MAX_REQUESTS_PER_PAGE = 200;
let observed = 0;

function trustedContext(): { tabUrl: string | null; tabId: number | null; isTopFrame: boolean } {
  return {
    tabUrl: window.location.href,
    tabId: null,
    isTopFrame: window.top === window.self,
  };
}

window.addEventListener('message', (event: MessageEvent) => {
  // Only messages from this frame and from the page's own origin are considered.
  if (event.source !== window) return;
  if (event.origin !== window.location.origin) return;
  if (observed >= MAX_REQUESTS_PER_PAGE) return;

  const parsed = pageObservationMessageSchema.safeParse(event.data);
  if (!parsed.success) return;

  const result = buildObservation(parsed.data, trustedContext());
  if (!result.ok) return;
  observed += 1;

  chrome.runtime.sendMessage({ kind: 'pv-observation', request: result.request }, (response: unknown) => {
    if (response === undefined || response === null) return;
    const view = (response as { view?: DecisionView }).view;
    if (view === undefined) return;
    if (view.dismissed_automatically) {
      clearOverlay();
      return;
    }
    renderOverlay(
      view,
      () =>
        chrome.runtime.sendMessage({
          kind: 'pv-force-allow',
          decision_id: (response as { decision_id?: string }).decision_id ?? null,
          // The page's own hostname (trusted context, like the observation's
          // origin): the background uses it to lift the network block when the
          // override succeeds.
          host: window.location.hostname,
        }),
      clearOverlay,
    );
  });
});

// Inject the main-world hook so fetch/XHR/beacon can be observed. The resource is
// bundled with the extension; the page never loads anything remote.
const hook = document.createElement('script');
hook.src = chrome.runtime.getURL('page-hook.js');
hook.async = false;
(document.head ?? document.documentElement).append(hook);
hook.remove();
