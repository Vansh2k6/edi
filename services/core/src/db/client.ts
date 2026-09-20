import { drizzle, type PostgresJsDatabase } from 'drizzle-orm/postgres-js';
import postgres, { type Sql } from 'postgres';
import * as schema from './schema.js';

/**
 * Postgres access.
 *
 * When `DATABASE_URL` is unset the core runs on its in-memory repository instead
 * (DEV-02), which is what makes the whole stack runnable without Docker. When it
 * is set, every connection sets `app.user_id` so row-level security applies.
 */
export interface DbHandle {
  db: PostgresJsDatabase<typeof schema>;
  close: () => Promise<void>;
  /** Run a callback with RLS scoped to one owner. */
  asOwner: <T>(userId: string, fn: (db: PostgresJsDatabase<typeof schema>) => Promise<T>) => Promise<T>;
}

export function createDb(databaseUrl: string, options: { max?: number } = {}): DbHandle {
  const client = postgres(databaseUrl, { max: options.max ?? 10 });
  const db = drizzle(client, { schema });

  return {
    db,
    close: () => client.end({ timeout: 5 }),
    async asOwner<T>(userId: string, fn: (scoped: PostgresJsDatabase<typeof schema>) => Promise<T>): Promise<T> {
      // `set_config(..., true)` scopes the setting to the current transaction.
      return client.begin(async (tx) => {
        // postgres-js hands the transaction a `TransactionSql`; drizzle accepts it
        // at runtime but its published types narrow the argument to the base client.
        const scoped = drizzle(tx as unknown as Sql, { schema });
        await tx`SELECT set_config('app.user_id', ${userId}, true)`;
        return fn(scoped);
      }) as unknown as Promise<T>;
    },
  };
}
