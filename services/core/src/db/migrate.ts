import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import postgres from 'postgres';
import { loadCoreConfig, repoRoot } from '../config.js';

/**
 * Applies every `infra/migrations/*.sql` file once, in filename order, and
 * records what it applied. Plain SQL stays reviewable and there is no ORM
 * migration state to reconcile.
 */
export async function migrate(databaseUrl: string, migrationsDir = join(repoRoot(), 'infra', 'migrations')): Promise<string[]> {
  const client = postgres(databaseUrl, { max: 1 });
  const applied: string[] = [];
  try {
    await client`CREATE TABLE IF NOT EXISTS schema_migrations (
      filename text PRIMARY KEY,
      applied_at timestamptz NOT NULL DEFAULT now()
    )`;
    const files = readdirSync(migrationsDir)
      .filter((name) => name.endsWith('.sql'))
      .sort();
    for (const file of files) {
      const already = await client`SELECT 1 FROM schema_migrations WHERE filename = ${file}`;
      if (already.length > 0) continue;
      const sql = readFileSync(join(migrationsDir, file), 'utf8');
      await client.unsafe(sql);
      await client`INSERT INTO schema_migrations (filename) VALUES (${file})`;
      applied.push(file);
    }
  } finally {
    await client.end({ timeout: 5 });
  }
  return applied;
}

const isDirectRun = process.argv[1]?.includes('migrate');

if (isDirectRun) {
  const config = loadCoreConfig();
  if (config.DATABASE_URL === undefined) {
    process.stdout.write(
      'DATABASE_URL is not set: the core runs on its in-memory repository, so there is nothing to migrate.\n',
    );
  } else {
    const applied = await migrate(config.DATABASE_URL);
    process.stdout.write(
      applied.length === 0 ? 'No pending migrations.\n' : `Applied migrations: ${applied.join(', ')}\n`,
    );
  }
}
