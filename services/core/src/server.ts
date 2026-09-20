import { categoryRegistryPath, loadCoreConfig, repoRoot } from './config.js';
import { loadCategories } from './categories.js';
import { buildApp, createDefaultDependencies } from './app.js';

/**
 * Startup order matters: configuration is validated, then the category registry,
 * then the app is built. Any failure stops the process with a named cause instead
 * of leaving a half-configured core listening for traffic.
 */
// Main bootstrap function that initializes and runs the privacy vault server
async function main(): Promise<void> {
  // Validate and load environment configuration from schemas
  const config = loadCoreConfig();
  // Load data category definitions and sensitivity levels from registry JSON
  const categories = loadCategories(categoryRegistryPath());
  // Instantiate core dependencies (database/in-memory repo, cache, crypto key provider, domain intel)
  const dependencies = createDefaultDependencies(config);
  // W8.1: the dashboard mounts when the deployment supplies its web secrets.
  // In development both secrets fall back to clearly-labeled dev values so a
  // local `npm run dev:core` boots a working dashboard; production refuses
  // placeholders, so those fallbacks only ever exist outside production.
  const devFallback = 'dev-only-web-secret-not-for-production-0000000';
  // Secret key used to sign HTTP session cookies
  const sessionSecret = config.SESSION_SECRET ?? (config.NODE_ENV === 'production' ? undefined : devFallback);
  // Master secret password required to log into the owner dashboard
  const ownerSecret = config.DASHBOARD_OWNER_SECRET ?? (config.NODE_ENV === 'production' ? undefined : 'dev-only-owner-secret-not-for-production');
  // Fixed UUID identifying the vault owner identity
  const ownerUserId = config.DASHBOARD_OWNER_USER_ID ?? (config.NODE_ENV === 'production' ? undefined : '11111111-1111-4111-8111-111111111111');
  // Construct Fastify application with configured routes, middleware, and security providers
  const app = buildApp({
    config,
    categories,
    repository: dependencies.repository,
    session: dependencies.session,
    keyProvider: dependencies.keyProvider,
    intelligence: dependencies.intelligence,
    deviceKeys: dependencies.deviceKeys,
    nonces: dependencies.nonces,
    deviceRegistrationEnabled: dependencies.deviceRegistrationEnabled,
    ...(sessionSecret === undefined || ownerSecret === undefined || ownerUserId === undefined ? {} : {
      web: {
        sessionSecret,
        ownerSecret,
        ownerUserId,
        dashboard: { distDir: `${repoRoot()}/apps/dashboard/dist` },
      },
    }),
    logger: true,
  });

  // Gracefully terminates HTTP server and shuts down database/provider connections
  const shutdown = async (signal: string): Promise<void> => {
    app.log.info({ signal }, 'shutting down');
    await app.close();
    await dependencies.close();
    process.exit(0);
  };
  process.on('SIGINT', () => void shutdown('SIGINT'));
  process.on('SIGTERM', () => void shutdown('SIGTERM'));

  // Start listening for inbound HTTP requests on configured host and port
  await app.listen({ port: config.CORE_PORT, host: '127.0.0.1' });
  app.log.info(
    {
      storage: dependencies.repository.kind,
      cache: dependencies.intelligence.cache.kind,
      key_provider: config.KEY_PROVIDER,
      providers: dependencies.intelligence.providers.map((provider) => provider.provider_id),
      device_registration: dependencies.deviceRegistrationEnabled,
    },
    'privacy vault core ready',
  );
}

main().catch((error: unknown) => {
  process.stderr.write(`core failed to start: ${error instanceof Error ? error.message : 'unknown error'}\n`);
  process.exit(1);
});
