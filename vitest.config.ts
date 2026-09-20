import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vitest/config';

const at = (path: string) => fileURLToPath(new URL(path, import.meta.url));

export default defineConfig({
  resolve: {
    alias: {
      '@pv/schemas': at('./packages/schemas/src/index.ts'),
      '@pv/crypto': at('./packages/crypto/src/index.ts'),
      '@pv/rules': at('./packages/rules/src/index.ts'),
      '@pv/domain-intel': at('./packages/domain-intel/src/index.ts'),
      '@pv/ui': at('./packages/ui/src/index.ts'),
    },
  },
  test: {
    environment: 'node',
    include: ['scripts/tests/**/*.test.ts'],
    // The log-privacy suite spawns a real child Node process running the full
    // app; under uncapped worker parallelism that child can be fail-fast
    // aborted by Windows at peak memory pressure (exit 0xC0000409), which
    // reads as a flaky suite rather than the resource contention it is. A
    // modest worker cap keeps the run deterministic on development machines.
    maxWorkers: 4,
  },
});
