#!/usr/bin/env node
/**
 * Build-absence gate (browser-harness.AC4.1 / AC4.2).
 *
 * Runs the production build and proves the browser test harness is physically absent
 * from it. The harness is only ever reached through a dynamic import gated on
 * `import.meta.env.DEV` in `src/hooks.client.ts`; Vite replaces that with `false` in a
 * production build, so Rollup drops the dynamic import and the whole harness chunk is
 * tree-shaken out. This script fails loudly if that guarantee ever regresses.
 *
 * Usage: `pnpm check:harness-absence` (or `node scripts/check-harness-absence.mjs`).
 */
import { execFileSync } from 'node:child_process';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

// The sentinel that `src/lib/harness/install.ts` embeds. Kept in sync by hand — it is a
// distinctive literal precisely so a stray copy in the bundle is unambiguous.
const MARKER = '__EZPDS_WALLET_HARNESS_PRESENT__';

const appDir = dirname(dirname(fileURLToPath(import.meta.url)));
const distDir = join(appDir, 'dist');

function run(cmd, args) {
  execFileSync(cmd, args, { cwd: appDir, stdio: 'inherit' });
}

function walk(dir) {
  const out = [];
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) out.push(...walk(full));
    else out.push(full);
  }
  return out;
}

console.log('[harness-absence] building production bundle…');
// Explicitly build WITHOUT the harness flag; even if it leaked into the env the DEV gate
// must still keep the harness out — that is exactly what this asserts.
run('pnpm', ['run', 'build']);

console.log('[harness-absence] scanning dist/ for the harness marker…');
const offenders = [];
for (const file of walk(distDir)) {
  // Only text-ish assets can carry the marker; skip obvious binaries by extension.
  if (/\.(png|jpg|jpeg|gif|woff2?|ttf|ico|wasm)$/i.test(file)) continue;
  const contents = readFileSync(file, 'utf8');
  if (contents.includes(MARKER)) offenders.push(file);
}

if (offenders.length > 0) {
  console.error(
    `\n[harness-absence] FAIL: harness marker '${MARKER}' found in production build:\n` +
      offenders.map((f) => `  - ${f}`).join('\n') +
      '\nThe harness must be tree-shaken out of production. Check the DEV gate in src/hooks.client.ts.'
  );
  process.exit(1);
}

console.log('[harness-absence] OK: no harness code in the production build.');
