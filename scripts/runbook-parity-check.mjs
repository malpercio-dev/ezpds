#!/usr/bin/env node
// Guard against the master-key disaster runbook drifting between its two copies:
//   - docs/operations/master-key-disaster-runbook.md   (canonical, engineering detail)
//   - sites/docs/.../operator/master-key-runbook.md     (published, operator-facing rewrite)
//
// The two are intentionally NOT identical (the site copy trims source file paths and
// migration versions), but the load-bearing facts — the golden rule and the
// quick-reference step ordering — must read the same everywhere an operator might land
// mid-incident. This extracts those anchors from the canonical doc and fails if the
// published copy doesn't contain them verbatim (modulo markdown line-wrap position).

import { readFileSync } from 'node:fs';
import { join } from 'node:path';

const root = new URL('..', import.meta.url).pathname;
const read = (path) => readFileSync(join(root, path), 'utf8');
const flatten = (text) => text.replace(/\s+/g, ' ').trim();

const REPO_PATH = 'docs/operations/master-key-disaster-runbook.md';
const SITE_PATH = 'sites/docs/src/content/docs/operator/master-key-runbook.md';

const repoFlat = flatten(read(REPO_PATH));
const siteFlat = flatten(read(SITE_PATH));

const ANCHORS = [
  ['golden rule', /\*\*Back up the KEK[^*]*?\*\*/],
  ['loss-scenario ordering', /\*\*Loss:\*\*.*?repo-key rotation\./],
  ['compromise-scenario ordering', /\*\*Compromise:\*\*.*?repo-key rotation\./],
];

let drifted = false;
for (const [label, regex] of ANCHORS) {
  const match = repoFlat.match(regex);
  if (!match) {
    console.error(`✗ runbook-parity: could not find the ${label} anchor in ${REPO_PATH}`);
    console.error('  (update the regex in scripts/runbook-parity-check.mjs if the wording changed intentionally)');
    drifted = true;
    continue;
  }
  if (!siteFlat.includes(match[0])) {
    console.error(`✗ runbook-parity: ${label} has drifted between the repo runbook and the published site page`);
    console.error(`  expected verbatim in ${SITE_PATH}:`);
    console.error(`  ${match[0]}`);
    drifted = true;
  }
}

if (drifted) {
  console.error(
    `\nThe golden rule and quick-reference ordering must stay word-for-word identical between\n${REPO_PATH} and ${SITE_PATH} — update both together (see the note at the top of each).`,
  );
  process.exit(1);
}

console.log('✓ runbook parity: golden rule + quick-reference ordering match between the repo runbook and the published site page');
