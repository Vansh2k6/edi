import { readdirSync, readFileSync, statSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

/**
 * Bundle guard (W8.8).
 *
 * The dashboard must contain no secrets and no third-party endpoints: every
 * network call target in the bundle must be a same-origin path, and the
 * bundle must never quote a secret-shaped value. The no-telemetry policy is
 * enforced here at build time, not by convention.
 */
const here = dirname(fileURLToPath(import.meta.url));
const dist = join(here, '..', 'dist');

function files(dir) {
  const out = [];
  for (const name of readdirSync(dir)) {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) out.push(...files(path));
    else out.push(path);
  }
  return out;
}

let failures = [];
for (const file of files(dist)) {
  const text = readFileSync(file, 'utf8');
  const rel = file.slice(dist.length + 1);

  // Secret-shaped assignments (long quoted values) must not exist at all.
  if (/(owner_secret|session_secret|grant_secret|api[_-]?key|token)\s*[:=]\s*['"][^'"]{16,}/i.test(text)) {
    failures.push(`${rel}: secret-shaped assignment`);
  }
  // Absolute third-party URLs: only same-origin paths and known-good
  // constants (schema dialect identifiers carried by the bundled validator,
  // not network calls) are allowed.
  const urls = text.match(/https?:\/\/[^\s"'`)]+/g) ?? [];
  for (const url of urls) {
    const allowed =
      url.startsWith('https://www.w3.org/') ||
      url.startsWith('http://www.w3.org/') ||
      url.startsWith('https://developer.mozilla.org/') ||
      url.startsWith('http://json-schema.org/') ||
      url.startsWith('https://json-schema.org/') ||
      // The bundled validator's IPv6 check probes a URL parser with a literal
      // template - a validation idiom, never a network call.
      url.startsWith('http://[') ||
      url === 'https://esbuild.github.io/';
    if (!allowed) failures.push(`${rel}: third-party endpoint ${url}`);
  }
}

if (failures.length > 0) {
  process.stderr.write(`dashboard bundle guard FAILED:\n${failures.map((f) => `  - ${f}`).join('\n')}\n`);
  process.exit(1);
}
process.stdout.write('dashboard bundle guard passed\n');
