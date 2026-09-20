import { readFileSync, readdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

/**
 * Bundle guard (`T008` least privilege, `AGENT.md`: no remote code).
 *
 * A store listing would reject most of this anyway, but the check belongs in CI
 * so a dependency that starts using `eval` fails the build instead of shipping.
 */
const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const dist = join(root, 'dist');

const FORBIDDEN = [
  { pattern: /\beval\s*\(/, label: 'eval(' },
  { pattern: /new\s+Function\s*\(/, label: 'new Function(' },
  { pattern: /import\s*\(\s*['"]https?:/, label: 'remote dynamic import' },
  { pattern: /<script[^>]+src=['"]https?:/, label: 'remote script tag' },
];

const offenders = [];
for (const file of readdirSync(dist)) {
  if (!file.endsWith('.js')) continue;
  const contents = readFileSync(join(dist, file), 'utf8');
  for (const { pattern, label } of FORBIDDEN) {
    if (pattern.test(contents)) offenders.push(`${file}: ${label}`);
  }
}

if (offenders.length > 0) {
  process.stderr.write(`extension bundle contains forbidden constructs:\n${offenders.join('\n')}\n`);
  process.exit(1);
}
process.stdout.write('extension bundle guard passed\n');
