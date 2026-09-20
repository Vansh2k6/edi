/**
 * Page-world hook (`W2.2`).
 *
 * Runs in the page's own world because that is the only place `fetch` and
 * `XMLHttpRequest` can be observed. Everything it sends is treated as untrusted
 * input by the content script: the channel name, mechanism and field names are
 * all it contributes.
 */

const CHANNEL = 'pv-observe';

function post(payload: Record<string, unknown>): void {
  window.postMessage({ channel: CHANNEL, ...payload }, window.location.origin);
}

function fieldNamesFromBody(body: unknown): string[] {
  try {
    if (typeof body === 'string') {
      const parsed: unknown = JSON.parse(body);
      if (parsed !== null && typeof parsed === 'object') return Object.keys(parsed as object).slice(0, 64);
      return [];
    }
    if (body instanceof FormData) return [...body.keys()].slice(0, 64);
    if (body instanceof URLSearchParams) return [...body.keys()].slice(0, 64);
  } catch {
    // A body we cannot read yields no field names; it never yields invented ones.
  }
  return [];
}

const originalFetch = window.fetch.bind(window);
window.fetch = async (input: RequestInfo | URL, init?: RequestInit) => {
  try {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
    const method = init?.method ?? (typeof input === 'object' && 'method' in input ? input.method : 'GET');
    post({ mechanism: 'fetch', url, method, field_names: fieldNamesFromBody(init?.body), page_claimed_origin: null });
  } catch {
    post({ mechanism: 'unsupported', url: window.location.href, method: '', field_names: [], page_claimed_origin: null });
  }
  return originalFetch(input as RequestInfo, init);
};

const OriginalXhr = window.XMLHttpRequest;

class ObservedXhr extends OriginalXhr {
  #method = '';
  #url = '';

  override open(method: string, url: string | URL, async?: boolean, username?: string | null, password?: string | null): void {
    try {
      this.#method = method;
      // Kept for send(): the body the page passes to send() belongs to the
      // request open() addressed, so the observation must carry both.
      this.#url = String(url);
      post({ mechanism: 'xhr', url: this.#url, method, field_names: [], page_claimed_origin: null });
    } catch {
      // Observation must never break the page's own request.
    }
    super.open(method, url, async ?? true, username ?? null, password ?? null);
  }

  override send(body?: Document | XMLHttpRequestBodyInit | null): void {
    try {
      post({
        mechanism: 'xhr',
        url: this.#url,
        method: this.#method,
        field_names: fieldNamesFromBody(body),
        page_claimed_origin: null,
      });
    } catch {
      // ignore
    }
    super.send(body ?? null);
  }
}

window.XMLHttpRequest = ObservedXhr as unknown as typeof XMLHttpRequest;

if (typeof navigator.sendBeacon === 'function') {
  const originalBeacon = navigator.sendBeacon.bind(navigator);
  navigator.sendBeacon = (url: string | URL, data?: BodyInit | null) => {
    try {
      post({ mechanism: 'beacon', url: String(url), method: 'POST', field_names: [], page_claimed_origin: null });
    } catch {
      // ignore
    }
    return originalBeacon(url, data ?? null);
  };
}
