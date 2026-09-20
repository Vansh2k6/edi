import { cpSync, mkdirSync, rmSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';

/**
 * Bundle the dashboard.
 *
 * Same discipline as the extension: esbuild is the only build dependency, the
 * shared packages are bundled in, and the output is exactly the static shell
 * the core serves under its strict first-party CSP.
 */
const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '..');
const outdir = join(root, 'dist');

rmSync(outdir, { recursive: true, force: true });
mkdirSync(outdir, { recursive: true });

await build({
  entryPoints: { app: join(root, 'src/main.ts') },
  outdir,
  entryNames: 'app',
  bundle: true,
  format: 'esm',
  target: ['es2022'],
  sourcemap: false,
  logLevel: 'warning',
  alias: {
    '@pv/schemas': join(root, '..', '..', 'packages', 'schemas', 'src', 'index.ts'),
    '@pv/ui': join(root, '..', '..', 'packages', 'ui', 'src', 'index.ts'),
  },
});

cpSync(join(root, 'public', 'index.html'), join(outdir, 'index.html'));
cpSync(join(root, 'public', 'styles.css'), join(outdir, 'styles.css'));
process.stdout.write(`dashboard built into ${outdir}\n`);
