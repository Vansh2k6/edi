import { cpSync, mkdirSync, rmSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';

/**
 * Bundle the extension.
 *
 * esbuild is the only build dependency: no bundler plugin ecosystem, no remote
 * code, and the shared `@pv/schemas` package is bundled in so the extension
 * validates the same contracts as the core.
 */
const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '..');
const outdir = join(root, 'dist');

rmSync(outdir, { recursive: true, force: true });
mkdirSync(outdir, { recursive: true });

await build({
  entryPoints: {
    background: join(root, 'src/background.ts'),
    content: join(root, 'src/content.ts'),
    'page-hook': join(root, 'src/page-hook.ts'),
  },
  outdir,
  bundle: true,
  format: 'esm',
  target: ['chrome116'],
  sourcemap: false,
  logLevel: 'warning',
  alias: {
    '@pv/schemas': join(root, '..', '..', 'packages', 'schemas', 'src', 'index.ts'),
    '@pv/ui': join(root, '..', '..', 'packages', 'ui', 'src', 'index.ts'),
  },
});

cpSync(join(root, 'public', 'manifest.json'), join(outdir, 'manifest.json'));
process.stdout.write(`extension built into ${outdir}\n`);
