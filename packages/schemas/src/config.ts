import { z } from 'zod';

/**
 * Process configuration (T002).
 *
 * Two rules this module must never break:
 *  1. A malformed configuration stops the process at start, naming the field.
 *  2. A rejected value is never echoed in the error, because the field may be a
 *     secret (AGENT.md: never log secrets, tokens or key material).
 */

export const nodeEnvSchema = z.enum(['development', 'test', 'production']);
export const keyProviderNameSchema = z.enum(['dev-shim', 'kms']);
export const logLevelSchema = z.enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace']);

/** Placeholder accepted in development and refused in production. */
export const DEV_PLACEHOLDER = 'dev-only-placeholder';

// Zod 4 note: `.optional()` is required here - a union containing z.undefined()
// still demands the key be present, which would break `.env` files that omit it.
// Protocol is constrained so a wrong-scheme value (say mysql://) is refused
// rather than accepted as "some URL".
const postgresUrl = z.url({ protocol: /^postgres(ql)?$/ }).optional();
const redisUrl = z.url({ protocol: /^rediss?$/ }).optional();
const optionalUrl = z.url().optional();

/** Connection strings must name a port explicitly (a silent default hides mistakes). */
const PORTED_FIELDS = ['DATABASE_URL', 'REDIS_URL'] as const;

function requirePort(value: string | undefined, field: string, ctx: z.RefinementCtx): void {
  if (value === undefined) return;
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    ctx.addIssue({ code: 'custom', path: [field], message: 'not a valid url' });
    return;
  }
  if (parsed.port === '') {
    ctx.addIssue({ code: 'custom', path: [field], message: 'a connection url must specify a port' });
  }
}

export const configSchema = z.strictObject({
  NODE_ENV: nodeEnvSchema,
  LOG_LEVEL: logLevelSchema,
  CORE_PORT: z.coerce.number().int().min(1).max(65535),

  /** Unset means the in-memory repository is used (DEV-02). */
  DATABASE_URL: postgresUrl,
  /** Unset means the in-process cache is used (DEV-03). */
  REDIS_URL: redisUrl,

  KEY_PROVIDER: keyProviderNameSchema,
  KEK_REF: z.string().min(1).max(256),

  /** HMAC secret for Force Allow authorization grants (W6.5). Optional so DEV setups run without it. */
  GRANT_SECRET: z.string().min(32).max(256).optional(),

  /** HMAC secret signing the dashboard's httpOnly session cookie (W8.1). Optional in development. */
  SESSION_SECRET: z.string().min(32).max(256).optional(),
  /** The credential the dashboard login form checks against (W8.1). Optional in development. */
  DASHBOARD_OWNER_SECRET: z.string().min(32).max(256).optional(),
  /** The one owner id the dashboard session represents (W8.1). Optional in development. */
  DASHBOARD_OWNER_USER_ID: z.uuid().optional(),

  DOMAIN_INTEL_CACHE_TTL_SECONDS: z.coerce.number().int().positive().max(604800),
  DOMAIN_INTEL_STALE_AFTER_SECONDS: z.coerce.number().int().positive().max(604800),
  DOMAIN_PROVIDER_TIMEOUT_MS: z.coerce.number().int().positive().max(10000),
  DOMAIN_PROVIDER_RETRIES: z.coerce.number().int().min(0).max(5),
  DOMAIN_PROVIDER_RATE_LIMIT_PER_MINUTE: z.coerce.number().int().positive().max(10000),

  DOMAIN_PROVIDER_ENDPOINT: optionalUrl,
  DOMAIN_PROVIDER_TOKEN: z.string().min(1).max(512).optional(),

  // Phase 9 retention (W9.3): windows are days per record type. A window of
  // zero is refused at configuration time, never at deletion time. Defaults
  // exist so a deployment that configures nothing still gets a documented,
  // finite window rather than an implicit forever.
  RETENTION_DAYS_AUDIT: z.coerce.number().int().positive().max(36500).default(365),
  RETENTION_DAYS_DECISION: z.coerce.number().int().positive().max(36500).default(180),
  RETENTION_DAYS_TOMBSTONE: z.coerce.number().int().positive().max(36500).default(30),
  RETENTION_BATCH_SIZE: z.coerce.number().int().positive().max(10000).default(500),
  RETENTION_WORKER_INTERVAL_SECONDS: z.coerce.number().int().positive().max(86400).default(3600),
}).superRefine((config, ctx) => {
  for (const field of PORTED_FIELDS) {
    requirePort(config[field], field, ctx);
  }
});

export type Config = z.infer<typeof configSchema>;

export class ConfigError extends Error {
  readonly fields: readonly string[];

  constructor(fields: readonly string[], detail?: string) {
    const list = fields.join(', ');
    super(
      detail
        ? `Invalid configuration: ${list} - ${detail} (values are not echoed)`
        : `Invalid configuration: ${list} (values are not echoed)`,
    );
    this.name = 'ConfigError';
    this.fields = fields;
  }
}

const KNOWN_KEYS = Object.keys(configSchema.shape) as (keyof Config)[];

/** The fields whose values are secret and may never be logged or echoed. */
export const SECRET_FIELDS = [
  'KEK_REF',
  'DOMAIN_PROVIDER_TOKEN',
  'DATABASE_URL',
  'REDIS_URL',
  'GRANT_SECRET',
  'SESSION_SECRET',
  'DASHBOARD_OWNER_SECRET',
] as const;

type RawEnv = Record<string, string | undefined>;

/**
 * Build the config input from process environment, ignoring unrelated variables
 * and normalising blank strings to `undefined` so that `.env.example` lines such
 * as `DATABASE_URL=` mean "not configured" rather than "empty string".
 */
function pickKnown(env: RawEnv): Record<string, string | undefined> {
  const out: Record<string, string | undefined> = {};
  for (const key of KNOWN_KEYS) {
    const raw = env[key];
    if (raw === undefined) continue;
    const trimmed = raw.trim();
    if (trimmed === '') continue;
    out[key] = trimmed;
  }
  return out;
}

export function parseConfig(env: RawEnv = process.env): Config {
  return configSchema.parse(pickKnown(env)) as Config;
}

/**
 * Non-throwing variant used by tests and by callers that want to report every
 * problem at once. Field paths only - never values.
 */
export function safeParseConfig(
  env: RawEnv,
): { ok: true; config: Config } | { ok: false; fields: string[]; error: ConfigError } {
  const result = configSchema.safeParse(pickKnown(env));
  if (result.success) {
    const config = result.data as Config;
    const refusal = productionPlaceholderRefusal(config);
    if (refusal) return { ok: false, fields: refusal, error: new ConfigError(refusal) };
    return { ok: true, config };
  }
  const fields = result.error.issues.map((issue) => issue.path.map(String).join('.') || '<root>');
  const unique = [...new Set(fields)];
  return { ok: false, fields: unique, error: new ConfigError(unique) };
}

/**
 * Production must never silently run on development placeholders (T002).
 * Returns the offending field names, or null when the configuration is usable.
 */
export function productionPlaceholderRefusal(config: Config): string[] | null {
  if (config.NODE_ENV !== 'production') return null;
  const offending: string[] = [];
  if (config.KEK_REF.includes(DEV_PLACEHOLDER)) offending.push('KEK_REF');
  if (config.KEY_PROVIDER === 'dev-shim') offending.push('KEY_PROVIDER');
  if (config.DOMAIN_PROVIDER_TOKEN?.includes(DEV_PLACEHOLDER)) offending.push('DOMAIN_PROVIDER_TOKEN');
  // A grant signing key from the source tree makes every Force Allow grant
  // forgeable, so production must supply one explicitly (W6.5).
  if (config.GRANT_SECRET === undefined) offending.push('GRANT_SECRET');
  // The web session and the dashboard login credential are the same class of
  // secret: a source-tree fallback would make dashboard sessions forgeable
  // and the login check decorative (W8.1).
  if (config.SESSION_SECRET === undefined) offending.push('SESSION_SECRET');
  if (config.DASHBOARD_OWNER_SECRET === undefined) offending.push('DASHBOARD_OWNER_SECRET');
  // The session must name its owner: a placeholder id would issue sessions
  // for an identity the vault has never seen.
  if (config.DASHBOARD_OWNER_USER_ID === undefined) offending.push('DASHBOARD_OWNER_USER_ID');
  if (offending.length > 0) {
    return offending;
  }
  return null;
}

/**
 * Load configuration or stop the process. Used once, at startup.
 */
export function loadConfigOrExit(env: RawEnv = process.env): Config {
  const parsed = safeParseConfig(env);
  if (!parsed.ok) {
    // Fields only: the ConfigError message never contains a value.
    process.stderr.write(`${parsed.error.message}\n`);
    process.exit(1);
  }
  return parsed.config;
}

export function defaultConfigForTest(overrides: Partial<Config> = {}): Config {
  return {
    NODE_ENV: 'test',
    LOG_LEVEL: 'error',
    CORE_PORT: 8080,
    DATABASE_URL: undefined,
    REDIS_URL: undefined,
    KEY_PROVIDER: 'dev-shim',
    KEK_REF: 'test-kek-ref',
    DOMAIN_INTEL_CACHE_TTL_SECONDS: 86400,
    DOMAIN_INTEL_STALE_AFTER_SECONDS: 21600,
    DOMAIN_PROVIDER_TIMEOUT_MS: 800,
    DOMAIN_PROVIDER_RETRIES: 2,
    DOMAIN_PROVIDER_RATE_LIMIT_PER_MINUTE: 60,
    DOMAIN_PROVIDER_ENDPOINT: undefined,
    DOMAIN_PROVIDER_TOKEN: undefined,
    SESSION_SECRET: undefined,
    DASHBOARD_OWNER_SECRET: undefined,
    DASHBOARD_OWNER_USER_ID: undefined,
    RETENTION_DAYS_AUDIT: 365,
    RETENTION_DAYS_DECISION: 180,
    RETENTION_DAYS_TOMBSTONE: 30,
    RETENTION_BATCH_SIZE: 500,
    RETENTION_WORKER_INTERVAL_SECONDS: 3600,
    ...overrides,
  };
}
