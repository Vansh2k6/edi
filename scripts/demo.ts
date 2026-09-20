import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createDeviceKeyPair, signRequest } from '@pv/envelope';
import { DevShimKeyProvider, nodeCipher, sealString, type EntryBinding } from '@pv/crypto';
import {
  createProviderRuntime,
  MemoryIntelligenceCache,
  type DomainIntelligenceProvider,
} from '@pv/domain-intel';
import { defaultConfigForTest, observedRequestSchema, type Config, type DomainSignal } from '@pv/schemas';
import { buildApp } from '../services/core/src/app.js';
import { loadCategories } from '../services/core/src/categories.js';
import { categoryRegistryPath } from '../services/core/src/config.js';
import { MemoryDeviceKeyRegistry, MemoryNonceStore } from '../services/core/src/device-auth.js';
import { MemoryVaultRepository } from '../services/core/src/repositories/vault-repository.js';

/**
 * Exit demo for Phases 0--4 (T001--T018).
 *
 * This runs the real application in-process against in-memory storage, so it
 * exercises the same routes, schemas and verification path as a deployment
 * without needing Docker. Run it with `npm run demo`.
 *
 * Every step below is named after the phase whose exit criteria it demonstrates,
 * and the refusals are printed as prominently as the successes: on this project a
 * rejected request is the feature.
 */

const OWNER = '11111111-1111-4111-8111-111111111111';
const tmp = mkdtempSync(join(tmpdir(), 'pv-demo-'));

function heading(text: string): void {
  process.stdout.write(`\n=== ${text} ===\n`);
}

function show(label: string, value: unknown): void {
  process.stdout.write(`${label}: ${JSON.stringify(value)}\n`);
}

/** A provider that answers, and one that is down, so "unknown" is observable. */
const reachableProvider: DomainIntelligenceProvider = {
  provider_id: 'demo-reputation',
  produces: ['reputation'],
  lookup: (): Promise<DomainSignal> =>
    Promise.resolve({
      type: 'reputation',
      value: 'suspicious',
      source: 'demo:reputation',
      retrieved_at: '2026-03-01T10:00:00.000Z',
      freshness: 'fresh',
      confidence: 0.7,
      unknown_reason: null,
      age_days: null,
    }),
};

const unreachableProvider: DomainIntelligenceProvider = {
  provider_id: 'demo-registration',
  produces: ['domain_age'],
  lookup: () => Promise.reject(new Error('provider unreachable')),
};

async function main(): Promise<void> {
  const config: Config = { ...defaultConfigForTest(), NODE_ENV: 'development' };
  const repository = new MemoryVaultRepository();
  const deviceKeys = new MemoryDeviceKeyRegistry();
  // The session is device-bound, which is what makes a signature mandatory rather
  // than optional: dropping the envelope is not a way to skip verification.
  const device = await createDeviceKeyPair();
  const app = buildApp({
    config,
    categories: loadCategories(categoryRegistryPath()),
    repository,
    session: {
      kind: 'static',
      resolve: () => Promise.resolve({ user_id: OWNER, actor: 'owner', device_key_id: device.keyId }),
    },
    keyProvider: new DevShimKeyProvider({
      kekFilePath: join(tmp, 'demo-kek.json'),
      kekRef: config.KEK_REF,
      nodeEnv: 'test',
    }),
    intelligence: {
      providers: [reachableProvider, unreachableProvider],
      cache: new MemoryIntelligenceCache(),
      state: createProviderRuntime(),
    },
    deviceKeys,
    nonces: new MemoryNonceStore({ windowMs: 60_000 }),
    deviceRegistrationEnabled: true,
  });

  const observationBase = {
    request_id: crypto.randomUUID(),
    timestamp: new Date().toISOString(),
    origin: {
      raw: 'https://shop.example.com/profile',
      host: 'shop.example.com',
      kind: 'public',
      scheme: 'https',
      port: null,
      registrable_domain: 'example.com',
      display: 'shop.example.com',
    },
    destination: 'https://tracker.example.net/collect',
    requested_data: ['email', 'phone', 'account_number'],
    mechanism: 'fetch',
    page_context: { top_level_url: 'https://shop.example.com/profile', is_top_frame: true },
    browser_context: { tab_id: 12, redirect_chain: [] },
  } as const;
  const observation = observationBase as unknown as Record<string, unknown>;

  heading('Phase 0 - contracts and configuration');
  const health = await app.inject({ method: 'GET', url: '/api/health' });
  show('GET /api/health', health.json());
  // The same strict schema every route validates with: an unknown field is an
  // error, so a client cannot inject "user_id" and have it silently ignored.
  const injected = observedRequestSchema.safeParse({ ...observationBase, user_id: 'attacker-supplied' });
  show('an injected field is refused', {
    ok: injected.success,
    fields: injected.success
      ? []
      : injected.error.issues.flatMap((issue) =>
          'keys' in issue ? issue.keys : issue.path.map(String),
        ),
  });

  heading('Phase 2 - device-bound signed transport');
  const registered = await app.inject({
    method: 'POST',
    url: '/api/devices',
    payload: { device_key_id: device.keyId, public_key: device.publicKeyBase64 },
  });
  show('registered device key', registered.json());


  const signed = await signRequest({ observation }, device);
  const analyzed = await app.inject({ method: 'POST', url: '/api/analyze', payload: { signed } });
  const analysis = analyzed.json() as Record<string, unknown>;
  show('signed POST /api/analyze - classification', analysis.classification);
  show('signed POST /api/analyze - feasibility', analysis.feasibility);
  show('signed POST /api/analyze - minimisation', analysis.minimization);

  const unsigned = await app.inject({ method: 'POST', url: '/api/analyze', payload: { observation } });
  show('unsigned request refused', unsigned.json());
  // Fresh nonce, so this demonstrates a broken signature rather than a reuse.
  const toTamper = await signRequest({ observation }, device);
  const tampered = await app.inject({
    method: 'POST',
    url: '/api/analyze',
    payload: { signed: { ...toTamper, body: { observation: { ...observation, requested_data: [] } } } },
  });
  show('tampered payload refused', tampered.json());
  const replayed = await app.inject({ method: 'POST', url: '/api/analyze', payload: { signed } });
  show('replayed envelope refused', replayed.json());
  const stranger = await app.inject({
    method: 'POST',
    url: '/api/analyze',
    payload: { signed: await signRequest({ observation }, await createDeviceKeyPair()) },
  });
  show('an unregistered key is refused, not trusted on first use', stranger.json());

  heading('Phase 3 - request classification is data-driven');
  const unrecognised = await app.inject({
    method: 'POST',
    url: '/api/analyze',
    payload: {
      signed: await signRequest(
        { observation: { ...observation, mechanism: 'beacon', requested_data: ['nric_number'] } },
        device,
      ),
    },
  });
  const unknownClassification = (unrecognised.json() as Record<string, unknown>).classification;
  show('a field no mapping knows is reported as unknown with a reason', unknownClassification);
  show('the facts carry no decision', (unrecognised.json() as Record<string, unknown>).decision);

  heading('Phase 4 - domain intelligence, where unknown is not safe');
  const intelligence = await app.inject({
    method: 'POST',
    url: '/api/domain-intelligence',
    payload: { signed: await signRequest({ host: 'tracker.example.net' }, device) },
  });
  const intel = intelligence.json() as { summary?: Record<string, unknown>; failures?: unknown[] };
  show('signals (one provider is down on purpose)', intel.summary?.signals ?? intel.summary);
  show('freshness and cache state', {
    cache: intel.summary?.cache,
    cache_state: intel.summary?.cache_state,
  });
  show('a provider outage is reported as a failure, never as a clean result', intel.failures);

  heading('Phase 1 - envelope-encrypted vault entry');
  // Sealed here exactly as a client would: the payload is encrypted before it is
  // sent, and the core only ever receives ciphertext plus a wrapped key.
  const dek = crypto.getRandomValues(new Uint8Array(32));
  const binding: EntryBinding = {
    data_id: crypto.randomUUID(),
    user_id: OWNER,
    data_category_id: 'CAT-IDENTITY',
  };
  const sealed = await sealString(nodeCipher, binding, dek, 'demo ciphertext payload');
  const uploaded = await app.inject({
    method: 'POST',
    url: '/api/vault/entries',
    payload: {
      signed: await signRequest(
        {
          data_category_id: 'CAT-IDENTITY',
          storage_tier: 'server',
          ciphertext: Buffer.from(sealed).toString('base64'),
          integrity_digest: 'b'.repeat(64),
          wrapped_dek: 'd3JhcHBlZA==',
        },
        device,
      ),
    },
  });
  const entry = uploaded.json() as Record<string, unknown>;
  show('stored entry (metadata only; the blob is not echoed back)', {
    data_id: entry.data_id,
    storage_tier: entry.storage_tier,
    data_status: entry.data_status,
  });

  const plaintextUpload = await app.inject({
    method: 'POST',
    url: '/api/vault/entries',
    payload: {
      signed: await signRequest(
        {
          data_category_id: 'CAT-IDENTITY',
          storage_tier: 'server',
          ciphertext: null,
          integrity_digest: 'b'.repeat(64),
          wrapped_dek: 'd3JhcHBlZA==',
          plaintext_data: 'my salary is 90000',
        },
        device,
      ),
    },
  });
  show('a plaintext field is refused (not stored, not logged)', plaintextUpload.json());

  // There is deliberately no read path that returns a blob: releasing data is the
  // vault gateway's job (Phase 7). Every advertised field below is metadata.
  const listed = await app.inject({ method: 'GET', url: '/api/vault/entries' });
  show('listing carries metadata only - no ciphertext, no wrapped key, no plaintext', listed.json());

  await app.close();
  process.stdout.write('\nexit demo complete\n');
}

main()
  .catch((error: unknown) => {
    process.stderr.write(`demo failed: ${error instanceof Error ? error.message : 'unknown error'}\n`);
    process.exitCode = 1;
  })
  .finally(() => {
    rmSync(tmp, { recursive: true, force: true });
  });
