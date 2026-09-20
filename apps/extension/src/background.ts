import { observedRequestSchema } from '@pv/schemas';
import { createDeviceKeyPair, signRequest, type SignedEnvelope } from '@pv/envelope';
import { toDecisionView, type DecisionView } from './decision-view.js';
import { buildEnforcementAttestation } from './enforcement.js';
import { installBlockRule, releaseBlockRule } from './block-rules.js';

/**
 * Background service worker.
 *
 * Responsibilities: keep the device key, forward signed observations to the core,
 * install network-level block rules for enforceable decisions, and report which
 * mechanisms it could not enforce (`T031`, `W2.4`).
 *
 * MV3 note: the worker is suspended when idle, so the device key lives in
 * IndexedDB rather than in module state.
 *
 * Replay protection lives entirely on the core: `signRequest` mints a fresh
 * nonce per call and the core's nonce store refuses reuse, so the client keeps
 * no nonce copy — stored nonces would be dead state suggesting a dedup
 * guarantee the client cannot provide.
 */

const CORE_URL = 'http://127.0.0.1:8080';
const DEVICE_KEY_DB = 'pv-keys';
const DEVICE_KEY_STORE = 'device';
const DEVICE_KEY_ID = 'primary';

/**
 * The device key persists in IndexedDB, not chrome.storage.
 *
 * The private key is non-extractable, so it cannot be exported to a JSON store;
 * IndexedDB structured-clones live CryptoKey objects, which keeps the key
 * material out of any serializable form entirely. The owner id is the dev-mode
 * session identity the core expects in `x-pv-dev-user` (real authentication
 * replaces both together, per the core's documented DEV-04 limitation).
 */
interface StoredKeyPair {
  keyId: string;
  pair: CryptoKeyPair;
  publicKeyBase64: string;
  ownerId: string;
}

function openKeyDatabase(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DEVICE_KEY_DB, 1);
    request.onupgradeneeded = () => {
      if (!request.result.objectStoreNames.contains(DEVICE_KEY_STORE)) {
        request.result.createObjectStore(DEVICE_KEY_STORE);
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error('indexedDB unavailable'));
  });
}

function idbGet(db: IDBDatabase, key: string): Promise<StoredKeyPair | undefined> {
  return new Promise((resolve, reject) => {
    const request = db.transaction(DEVICE_KEY_STORE, 'readonly').objectStore(DEVICE_KEY_STORE).get(key);
    request.onsuccess = () => resolve(request.result as StoredKeyPair | undefined);
    request.onerror = () => reject(request.error ?? new Error('indexedDB read failed'));
  });
}

function idbPut(db: IDBDatabase, key: string, value: StoredKeyPair): Promise<void> {
  return new Promise((resolve, reject) => {
    const request = db.transaction(DEVICE_KEY_STORE, 'readwrite').objectStore(DEVICE_KEY_STORE).put(value, key);
    request.onsuccess = () => resolve();
    request.onerror = () => reject(request.error ?? new Error('indexedDB write failed'));
  });
}

async function getDevice(): Promise<{ record: StoredKeyPair; fresh: boolean }> {
  try {
    const db = await openKeyDatabase();
    try {
      const stored = await idbGet(db, DEVICE_KEY_ID);
      if (stored) return { record: stored, fresh: false };
      const created = await createDeviceKeyPair();
      const record: StoredKeyPair = {
        keyId: created.keyId,
        pair: created.pair,
        publicKeyBase64: created.publicKeyBase64,
        ownerId: crypto.randomUUID(),
      };
      await idbPut(db, DEVICE_KEY_ID, record);
      return { record, fresh: true };
    } finally {
      db.close();
    }
  } catch {
    // IndexedDB unavailable: an ephemeral key keeps signing working, and the
    // core refuses the unregistered key id rather than trusting it on first use.
    const created = await createDeviceKeyPair();
    return {
      record: {
        keyId: created.keyId,
        pair: created.pair,
        publicKeyBase64: created.publicKeyBase64,
        ownerId: crypto.randomUUID(),
      },
      fresh: true,
    };
  }
}

/**
 * Register the device key with the core.
 *
 * Without this the core refuses every signature with `unknown_device_key`:
 * the extension used to create a key it never registered. Registration rides
 * on the development session header, exactly as the core documents.
 */
async function registerDevice(record: StoredKeyPair): Promise<boolean> {
  const response = await fetch(`${CORE_URL}/api/devices`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-pv-dev-user': record.ownerId },
    body: JSON.stringify({ device_key_id: record.keyId, public_key: record.publicKeyBase64 }),
  });
  return response.ok;
}

/**
 * POST a signed request.
 *
 * The payload travels inside the envelope, so the core verifies the signature
 * over exactly the value it then acts on - and a large body is never duplicated
 * into a header, where the server's header size limit would truncate it.
 */
async function postToCore(path: string, body: unknown): Promise<{ status: number; json: unknown }> {
  const { record: device, fresh } = await getDevice();
  if (fresh) await registerDevice(device);
  const envelope: SignedEnvelope = await signRequest(body, device);
  const response = await fetch(`${CORE_URL}${path}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-pv-dev-user': device.ownerId },
    body: JSON.stringify({ signed: envelope }),
  });
  let json: unknown = await response.json().catch(() => null);
  // The core's device registry is in-memory, so a core restart revokes every
  // registration. Re-register and retry once instead of dead-ending the flow.
  if (
    response.status === 401 &&
    (json as { error?: string } | null)?.error === 'unknown_device_key' &&
    (await registerDevice(device))
  ) {
    const retryEnvelope: SignedEnvelope = await signRequest(body, device);
    const retry = await fetch(`${CORE_URL}${path}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-pv-dev-user': device.ownerId },
      body: JSON.stringify({ signed: retryEnvelope }),
    });
    json = await retry.json().catch(() => null);
    return { status: retry.status, json };
  }
  return { status: response.status, json };
}

interface ObservationMessage {
  kind: 'pv-observation';
  request: unknown;
}

interface ForceAllowMessage {
  kind: 'pv-force-allow';
  decision_id: string | null;
  /** The page's own host, used to lift the network block on a successful override. */
  host?: string;
}

chrome.runtime.onMessage.addListener(
  (message: ObservationMessage | ForceAllowMessage, _sender, sendResponse: (response: unknown) => void) => {
    void (async () => {
      if (message.kind === 'pv-force-allow') {
        if (message.decision_id === null) {
          sendResponse({ ok: false, error: 'no_decision' });
          return;
        }
        const result = await postToCore('/api/decisions/override', {
          decision_id: message.decision_id,
          reason: 'owner override from the extension overlay',
        });
        if (result.status === 200 && message.host) {
          // The owner released this page: the network block installed for its
          // host must go with it. The rule is per host, and the next blocked
          // request re-installs it, so the release never outlives the policy.
          await releaseBlockRule(chrome.declarativeNetRequest, message.host);
        }
        sendResponse(result);
        return;
      }

      const parsed = observedRequestSchema.safeParse(message.request);
      if (!parsed.success) {
        sendResponse({ ok: false, error: 'invalid_observation' });
        return;
      }
      const observation = parsed.data;
      const response = await postToCore('/api/decisions/evaluate', { observation });
      if (response.status !== 200 || response.json === null) {
        sendResponse({ ok: false, error: 'core_unavailable' });
        return;
      }
      const decision = response.json as Parameters<typeof toDecisionView>[0];
      // Enforcement follows the decision. A block installs (or replaces) the
      // host's network rule; an allow or warn lifts it, so a policy change
      // cannot leave a host network-blocked forever. ASK_USER keeps the block
      // until the owner answers, and only an actually installed rule is
      // attested as enforced (D-025).
      let attestation: ReturnType<typeof buildEnforcementAttestation> = null;
      if (decision.decision === 'BLOCK') {
        const installed = await installBlockRule(chrome.declarativeNetRequest, observation.origin.host);
        attestation = buildEnforcementAttestation(installed, observation.mechanism, decision.matched_rules[0] ?? null);
      } else if (decision.decision !== 'ASK_USER') {
        await releaseBlockRule(chrome.declarativeNetRequest, observation.origin.host);
      }
      const enforced = attestation?.enforced ?? true;
      const view: DecisionView = toDecisionView(decision, { enforced, mechanism: observation.mechanism });
      sendResponse({ ok: true, view, enforced, decision_id: decision.decision_id, attestation });
    })();
    // Keep the message channel open for the async response.
    return true;
  },
);

/**
 * Content scripts are registered per granted origin rather than declared with a
 * broad host pattern, so the extension asks for access to a site instead of
 * holding it from install time (least privilege, `T008`).
 *
 * Registration is idempotent: `registerContentScripts` persists across service
 * worker restarts, and a duplicate id would throw.
 */
export async function ensureContentScriptRegistered(origin: string): Promise<boolean> {
  const pattern = `${origin}/*`;
  const granted = await chrome.permissions.contains({ origins: [pattern] });
  if (!granted) return false;
  const id = `pv-content-${origin}`;
  const registered = await chrome.scripting.getRegisteredContentScripts();
  if (registered.some((script) => script.id === id)) return true;
  await chrome.scripting.registerContentScripts([
    {
      id,
      matches: [pattern],
      js: ['content.js'],
      runAt: 'document_start',
    },
  ]);
  return true;
}

/**
 * Wire the observation pipeline.
 *
 * Without these listeners nothing ever injects `content.js` into a page and the
 * extension cannot observe a single request — the pipeline is dead before it
 * starts. The toolbar click is the user gesture that grants per-site access;
 * every later navigation re-checks registration so the mapping survives both
 * browser restarts and newly granted origins.
 */
chrome.action.onClicked.addListener((tab) => {
  void (async () => {
    if (tab.url === undefined || tab.url === '') return;
    let origin: string;
    try {
      origin = new URL(tab.url).origin;
    } catch {
      return;
    }
    if (origin === 'chrome-extension://') return;
    const granted = await chrome.permissions.request({ origins: [`${origin}/*`] });
    if (!granted) return;
    const activated = await ensureContentScriptRegistered(origin);
    if (tab.id !== undefined) {
      await chrome.action.setBadgeText({ tabId: tab.id, text: activated ? 'ON' : '' });
    }
  })();
});

chrome.webNavigation.onCommitted.addListener((details) => {
  if (details.frameId !== 0) return;
  void (async () => {
    const origin = new URL(details.url).origin;
    await ensureContentScriptRegistered(origin);
  })().catch(() => undefined);
});
