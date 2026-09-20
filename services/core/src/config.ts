import { existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadConfigOrExit, type Config } from '@pv/schemas';

/**
 * Configuration entry point (T002).
 *
 * `.env` is loaded when present and never committed. Validation happens once,
 * here, so no later code path can run on an unvalidated value.
 */
export function repoRoot(): string {
  // services/core/src -> repository root
  return join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..');
}

export function loadCoreConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const envPath = join(repoRoot(), '.env');
  if (existsSync(envPath) && typeof process.loadEnvFile === 'function') {
    try {
      process.loadEnvFile(envPath);
    } catch {
      // A malformed .env file is reported by the validation below, not here.
    }
  }
  return loadConfigOrExit(env);
}

export function devKekPath(): string {
  return join(repoRoot(), 'infra', 'kms-dev', 'dev-kek.json');
}

export function categoryRegistryPath(): string {
  return join(repoRoot(), 'infra', 'categories.json');
}

/** The shipped, checksum-verified ruleset backing the decision engine (W5.3). */
export function rulesetPath(): string {
  return join(repoRoot(), 'packages', 'rules', 'ruleset', 'v1', 'ruleset.json');
}
