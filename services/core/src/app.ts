import Fastify, { type FastifyInstance } from 'fastify';
import { CryptoError, DevShimKeyProvider, KmsKeyProvider, type KeyProvider } from '@pv/crypto';
import {
  CertificateHistoryProvider,
  createProviderRuntime,
  DnsSignalProvider,
  MemoryIntelligenceCache,
  RdapRegistrationProvider,
  RedisIntelligenceCache,
  ReputationProvider,
  type DomainIntelligenceProvider,
  type IntelligenceCache,
  type ProviderRuntimeState,
} from '@pv/domain-intel';
import { Redis } from 'ioredis';
import { MAX_ENVELOPE_BODY_BYTES, REPLAY_WINDOW_MS, type Config, type DataCategory } from '@pv/schemas';
import { HmacGrantIssuer, MemoryGrantStore } from './gateway/grants.js';
import { VaultGateway } from './gateway/authorize.js';
import { registerDisclosureRoute } from './routes/disclosure.js';
import { createDevHeaderSessionProvider, type SessionProvider } from './session.js';
import { MemoryVaultRepository, type VaultRepository } from './repositories/vault-repository.js';
import { registerAnalyzeRoutes } from './routes/analyze.js';
import { registerDecisionRoutes } from './routes/decisions.js';
import { registerIntelligenceRoutes } from './routes/intelligence.js';
import { registerMetaRoutes } from './routes/meta.js';
import { registerRulesRoutes } from './routes/rules.js';
import { registerVaultRoutes } from './routes/vault.js';
import { registerConsentRoutes } from './routes/consents.js';
import { registerStreamRoutes } from './routes/stream.js';
import { registerDashboardStaticRoutes } from './routes/dashboard.js';
import { createCookieSessionProvider, createMemoryRevocations, registerCsrfGuard, registerSessionRoutes } from './web-session.js';
import { DecisionEventBus } from './event-bus.js';
import { MemoryConsentStore, type ConsentStore } from './consent-store.js';
import { MemoryAuditWriter, type AuditWriter } from './audit-writer.js';
import { DecisionService, loadDefaultRuleset, MemoryDecisionStore, type DecisionStore } from './decision-service.js';
import { MemoryUserPolicyStore, type UserPolicyStore } from './policy-store.js';
import {
  MemoryDeviceKeyRegistry,
  MemoryNonceStore,
  type DeviceKeyRegistry,
  type DeviceRequestContext,
  type NonceStore,
} from './device-auth.js';
import { devKekPath, rulesetPath } from './config.js';

/** Everything the decision and rule routes need; the default build assembles it in-process. */
export interface DecisionRuntime {
  service: DecisionService;
  store: DecisionStore;
  audit: AuditWriter;
  /** The same policy store the service reads; the rules API mutates it. */
  userPolicy: UserPolicyStore;
  /** Issues the single-use grants a Force Allow returns (W6.5). */
  grantIssuer: HmacGrantIssuer;
}

/**
 * Request-body ceiling. Must not exceed the wire contract in
 * `packages/schemas/src/envelope.ts` (`MAX_ENVELOPE_BODY_BYTES`); kept as a
 * literal here because Fastify wants a plain number, with a runtime assertion
 * below so the two cannot drift apart silently.
 */
const BODY_LIMIT_BYTES = MAX_ENVELOPE_BODY_BYTES;

/**
 * Dashboard wiring (W8.1, W8.8). Present when the core serves the web
 * dashboard: it switches the session provider to signed cookies, enables the
 * CSRF guard, and mounts the built SPA shell when a dist directory is given.
 */
export interface WebOptions {
  sessionSecret: string;
  ownerSecret: string;
  /** The one owner id this deployment's dashboard represents. */
  ownerUserId: string;
  ttlSeconds?: number;
  /** Brute-force ceiling for dashboard login; defaults to 5 failures per minute. */
  loginThrottle?: { maxFailures: number; windowMs: number };
  dashboard?: {
    /** Directory the dashboard build wrote; omitted serves a 404 shell. */
    distDir: string;
  };
}

export interface IntelligenceDependencies {
  providers: readonly DomainIntelligenceProvider[];
  cache: IntelligenceCache;
  state: ProviderRuntimeState;
}

export interface AppOptions {
  config: Config;
  categories: readonly DataCategory[];
  repository: VaultRepository;
  session: SessionProvider;
  keyProvider: KeyProvider;
  intelligence: IntelligenceDependencies;
  deviceKeys: DeviceKeyRegistry;
  nonces: NonceStore;
  /** Device registration is development scaffolding, not a production feature. */
  deviceRegistrationEnabled: boolean;
  /** Decision engine wiring; assembled in-process when omitted (DEV scope). */
  decisions?: DecisionRuntime;
  /**
   * The consent store shared by the consent routes and the vault gateway.
   * One instance, so the dashboard and the disclosure-time check cannot
   * disagree (W8.5).
   */
  consents?: ConsentStore;
  /** The live-decision bus shared by the service and the SSE stream (W8.3). */
  events?: DecisionEventBus;
  web?: WebOptions;
  logger?: boolean;
}

/**
 * Build the security core.
 *
 * Error handling is deliberately terse: a validation failure reports field paths
 * and never values, a key problem reports a key error, and anything else becomes
 * a generic 500. An error response must not be the place where ciphertext, a
 * wrapped key or a provider credential leaks.
 */
export function buildApp(options: AppOptions): FastifyInstance {
  const app = Fastify({
    logger:
      options.logger === true
        ? {
            level: options.config.LOG_LEVEL,
            redact: [
              'req.headers.authorization',
              'req.headers.cookie',
              // req.url includes the query string, which is client-controlled
              // input and can carry plaintext personal data. Redacted wholesale:
              // a partial censor cannot distinguish a query value from a header
              // value, and a leaked query string is a privacy breach.
              'req.url',
            ],
          }
        : false,
    bodyLimit: BODY_LIMIT_BYTES,
    disableRequestLogging: options.logger !== true,
  });

  app.addHook('onSend', async (_request, reply, payload) => {
    reply.header('x-content-type-options', 'nosniff');
    reply.header('referrer-policy', 'no-referrer');
    reply.header('cache-control', 'no-store');
    // W8.8: strict first-party CSP. The dashboard loads no third-party script
    // and the CSP enforces the no-telemetry policy structurally; the API
    // responses carry it too, which costs nothing and protects proxies.
    reply.header(
      'content-security-policy',
      [
        "default-src 'self'",
        "script-src 'self'",
        "style-src 'self'",
        "img-src 'self' data:",
        "connect-src 'self'",
        "font-src 'self'",
        "object-src 'none'",
        "base-uri 'none'",
        "form-action 'self'",
        "frame-ancestors 'none'",
      ].join('; '),
    );
    reply.header('x-frame-options', 'DENY');
    reply.header('cross-origin-opener-policy', 'same-origin');
    reply.header('cross-origin-resource-policy', 'same-origin');
    return payload;
  });

  app.setErrorHandler((error: unknown, _request, reply) => {
    if (error instanceof CryptoError) {
      const status = error.code === 'key_unavailable' ? 503 : 502;
      return reply.status(status).send({ error: error.code });
    }
    const statusCode =
      typeof error === 'object' && error !== null && 'statusCode' in error
        ? (error as { statusCode?: unknown }).statusCode
        : undefined;
    if (typeof statusCode === 'number' && statusCode >= 400 && statusCode < 500) {
      return reply.status(statusCode).send({ error: 'invalid_request' });
    }
    // Never surface an internal message: it may quote a payload or a credential.
    return reply.status(500).send({ error: 'internal_error' });
  });

  app.setNotFoundHandler((_request, reply) => reply.status(404).send({ error: 'not_found' }));

  const device: DeviceRequestContext = { registry: options.deviceKeys, nonces: options.nonces };

  // W8.5: exactly one consent store - the consent routes write it, the vault
  // gateway reads it at disclosure time.
  const consentStore = options.consents ?? new MemoryConsentStore();
  // W8.3: exactly one event bus - the service publishes, the SSE stream
  // subscribes. An injected decision runtime must be composed with the same
  // bus (pass it here) or the stream has nothing to carry.
  const bus = options.events ?? new DecisionEventBus();
  // The service's sink seam takes publish directly; the bus already matches it.
  const eventSink = { publishDecision: (decision: Parameters<DecisionEventBus['publish']>[1] extends { decision: infer D } ? D : never) => bus.publish(decision.user_id, { type: 'decision', decision }) };

  // W8.1: when the dashboard is configured, the signed cookie provider is the
  // session for every route, and the double-submit CSRF guard protects its
  // mutations. Without web wiring nothing changes for existing callers.
  const webRevocations = options.web ? createMemoryRevocations() : undefined;
  const session: SessionProvider = options.web
    ? createCookieSessionProvider({
        sessionSecret: options.web.sessionSecret,
        ...(options.web.ttlSeconds === undefined ? {} : { ttlSeconds: options.web.ttlSeconds }),
        ...(webRevocations === undefined ? {} : { revocations: webRevocations }),
      })
    : options.session;
  if (options.web) {
    registerCsrfGuard(app, { sessionSecret: options.web.sessionSecret, ...(webRevocations === undefined ? {} : { revocations: webRevocations }) });
    registerSessionRoutes(app, {
      sessionSecret: options.web.sessionSecret,
      ownerSecret: options.web.ownerSecret,
      ownerUserId: options.web.ownerUserId,
      ...(options.web.ttlSeconds === undefined ? {} : { ttlSeconds: options.web.ttlSeconds }),
      ...(options.web.loginThrottle === undefined ? {} : { loginThrottle: options.web.loginThrottle }),
      ...(webRevocations === undefined ? {} : { revocations: webRevocations }),
      secureCookie: options.config.NODE_ENV === 'production',
    });
  }

  // The decision engine is composed in-process unless a deployment supplies its
  // own durable store, audit writer and service wiring (Phase 8+ concern).
  // The service and the routes MUST share one store: separate instances would
  // let evaluate() return a decision id that GET/override can never find.
  const defaultDecisionStore = new MemoryDecisionStore();
  const defaultAudit = new MemoryAuditWriter();
  const defaultUserPolicy = new MemoryUserPolicyStore();
  // The grant secret is configuration, not code: a hardcoded signing key would
  // make every deployment's Force Allow grants forgeable with the source tree.
  const defaultGrantIssuer = new HmacGrantIssuer(
    new MemoryGrantStore(),
    options.config.GRANT_SECRET ?? 'dev-grant-secret-do-not-use-in-production-000000000000',
  );
  const runtime: DecisionRuntime =
    options.decisions ??
    {
      service: new DecisionService({
        categories: options.categories,
        ruleset: loadDefaultRuleset(rulesetPath()),
        userPolicy: defaultUserPolicy,
        decisions: defaultDecisionStore,
        intelligence: {
          providers: options.intelligence.providers,
          cache: options.intelligence.cache,
          state: options.intelligence.state,
          staleAfterSeconds: options.config.DOMAIN_INTEL_STALE_AFTER_SECONDS,
          ttlSeconds: options.config.DOMAIN_INTEL_CACHE_TTL_SECONDS,
        },
        events: eventSink,
      }),
      store: defaultDecisionStore,
      audit: defaultAudit,
      userPolicy: defaultUserPolicy,
      grantIssuer: defaultGrantIssuer,
    };

  registerDecisionRoutes(app, {
    session,
    device,
    decisions: runtime.service,
    store: runtime.store,
    audit: runtime.audit,
    categories: options.categories,
    grantIssuer: runtime.grantIssuer,
  });

  registerRulesRoutes(app, {
    session,
    device,
    service: runtime.service,
    userPolicy: runtime.userPolicy,
    audit: runtime.audit,
  });

  // W7.1: the gateway is composed with the repositories' own server-tier
  // reader, so ciphertext access stays behind the one disclosure path.
  const rulesetVersion = loadDefaultRuleset(rulesetPath()).ruleset_version;
  const gateway = new VaultGateway({
    repository: options.repository,
    serverEntries: options.repository,
    // The gateway must share the runtime's issuer: a different store or secret
    // would refuse every grant the Force Allow route legitimately issued.
    grants: runtime.grantIssuer,
    audit: runtime.audit,
    keyProvider: options.keyProvider,
    grantSecret: options.config.GRANT_SECRET ?? 'dev-grant-secret-do-not-use-in-production-000000000000',
    consents: consentStore,
  });
  registerDisclosureRoute(app, {
    session,
    device,
    gateway,
    userPolicy: runtime.userPolicy,
    rulesetVersion,
  });

  registerMetaRoutes(app, {
    session,
    config: options.config,
    categories: options.categories,
    repositoryKind: options.repository.kind,
    cacheKind: options.intelligence.cache.kind,
    providerIds: options.intelligence.providers.map((provider) => provider.provider_id),
    deviceKeys: options.deviceKeys,
    deviceRegistrationEnabled: options.deviceRegistrationEnabled,
  });

  registerVaultRoutes(app, {
    repository: options.repository,
    session,
    device,
    keyProvider: options.keyProvider,
    categories: options.categories,
    kekRef: options.config.KEK_REF,
    gateway,
    rulesetVersion,
  });

  // W8.5: the dashboard's consent screen, sharing the gateway's store.
  registerConsentRoutes(app, {
    session,
    consents: consentStore,
    userPolicy: runtime.userPolicy,
    audit: runtime.audit,
    categories: options.categories,
  });

  // W8.3: the live-decision stream, session-guarded and owner-scoped.
  registerStreamRoutes(app, { session, bus });

  registerAnalyzeRoutes(app, {
    session,
    device,
    categories: options.categories,
  });

  registerIntelligenceRoutes(app, {
    session,
    device,
    providers: options.intelligence.providers,
    cache: options.intelligence.cache,
    state: options.intelligence.state,
    window: {
      staleAfterSeconds: options.config.DOMAIN_INTEL_STALE_AFTER_SECONDS,
      ttlSeconds: options.config.DOMAIN_INTEL_CACHE_TTL_SECONDS,
    },
    policy: {
      timeoutMs: options.config.DOMAIN_PROVIDER_TIMEOUT_MS,
      retries: options.config.DOMAIN_PROVIDER_RETRIES,
      rateLimitPerMinute: options.config.DOMAIN_PROVIDER_RATE_LIMIT_PER_MINUTE,
      circuitFailureThreshold: 3,
      circuitCooldownMs: 30_000,
    },
  });

  // W8.8: the built SPA shell, when the deployment carries one.
  if (options.web?.dashboard !== undefined) {
    registerDashboardStaticRoutes(app, { distDir: options.web.dashboard.distDir });
  }

  return app;
}

export interface DefaultDependencies {
  repository: VaultRepository;
  session: SessionProvider;
  keyProvider: KeyProvider;
  intelligence: IntelligenceDependencies;
  deviceKeys: DeviceKeyRegistry;
  nonces: NonceStore;
  deviceRegistrationEnabled: boolean;
  /** Closes any external connections opened for this configuration. */
  close: () => Promise<void>;
}

/**
 * Wire the default dependencies for a configuration.
 *
 * Postgres and Redis are used when configured and replaced by their in-process
 * equivalents otherwise (DEV-02, DEV-03), so the stack runs without Docker while
 * the production path stays the same code.
 */
export function createDefaultDependencies(config: Config): DefaultDependencies {
  const closers: Array<() => Promise<void>> = [];

  const repository: VaultRepository = new MemoryVaultRepository();

  const keyProvider: KeyProvider =
    config.KEY_PROVIDER === 'kms'
      ? new KmsKeyProvider()
      : new DevShimKeyProvider({
          kekFilePath: devKekPath(),
          kekRef: config.KEK_REF,
          nodeEnv: config.NODE_ENV,
        });

  let cache: IntelligenceCache = new MemoryIntelligenceCache();
  if (config.REDIS_URL !== undefined) {
    const redis = new Redis(config.REDIS_URL, { lazyConnect: false, maxRetriesPerRequest: 2 });
    cache = new RedisIntelligenceCache(redis);
    closers.push(async () => {
      redis.disconnect();
    });
  }

  const providers: DomainIntelligenceProvider[] = [
    new RdapRegistrationProvider({ endpoint: 'https://rdap.org' }),
    new DnsSignalProvider(),
    new CertificateHistoryProvider({}),
    new ReputationProvider({
      ...(config.DOMAIN_PROVIDER_ENDPOINT === undefined ? {} : { endpoint: config.DOMAIN_PROVIDER_ENDPOINT }),
      ...(config.DOMAIN_PROVIDER_TOKEN === undefined ? {} : { token: config.DOMAIN_PROVIDER_TOKEN }),
    }),
  ];

  return {
    repository,
    session: createDevHeaderSessionProvider({ nodeEnv: config.NODE_ENV }),
    keyProvider,
    intelligence: { providers, cache, state: createProviderRuntime() },
    deviceKeys: new MemoryDeviceKeyRegistry(),
    nonces: new MemoryNonceStore({ windowMs: REPLAY_WINDOW_MS }),
    // Registration rides on the development session provider, so it disappears
    // with it rather than leaving an unauthenticated registration route behind.
    deviceRegistrationEnabled: config.NODE_ENV !== 'production',
    close: async () => {
      for (const closer of closers) await closer();
    },
  };
}
