// Local persistent state: test-account credentials (including did:plc rotation
// keys — the actual root of control) and the ledger of interaction records we
// have written and must clean up. Lives under .state/ (gitignored, chmod 0600).

import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

const STATE_DIR = process.env.EZPDS_INTEROP_STATE_DIR
  ?? path.join(path.dirname(fileURLToPath(import.meta.url)), '..', '.state');
const STATE_FILE = path.join(STATE_DIR, 'state.json');

export function statePaths() {
  return { dir: STATE_DIR, file: STATE_FILE };
}

export function loadState() {
  try {
    return JSON.parse(fs.readFileSync(STATE_FILE, 'utf8'));
  } catch (err) {
    if (err.code === 'ENOENT') return { accounts: {}, interactions: [] };
    throw err;
  }
}

export function saveState(state) {
  fs.mkdirSync(STATE_DIR, { recursive: true, mode: 0o700 });
  const tmp = `${STATE_FILE}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(state, null, 2) + '\n', { mode: 0o600 });
  fs.renameSync(tmp, STATE_FILE);
}

export function getAccount(state, name) {
  const account = state.accounts[name];
  if (!account) {
    const known = Object.keys(state.accounts);
    throw new Error(`no account named "${name}" in state${known.length ? ` (known: ${known.join(', ')})` : ' — run create-account first'}`);
  }
  return account;
}

export function writeReport(report) {
  const dir = path.join(STATE_DIR, 'reports');
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const file = path.join(dir, `report-${new Date().toISOString().replace(/[:.]/g, '-')}.json`);
  fs.writeFileSync(file, JSON.stringify(report, null, 2) + '\n', { mode: 0o600 });
  return file;
}
