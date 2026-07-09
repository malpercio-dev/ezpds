// Cached credentials for one PDS: the agent registration and the tokens minted
// from it. One JSON file per PDS host under the OS state dir (see config.ts),
// written 0600 — tokens never go anywhere else (not logs, not MCP responses).

import * as fs from 'node:fs';
import * as path from 'node:path';
import { stateDir } from './config.ts';

export interface CachedCredentials {
  /** Base URL of the PDS these credentials belong to. */
  pdsUrl: string;
  /** Registration id returned by POST /agent/identity. */
  registrationId?: string;
  /** The service-signed identity assertion (JWT) exchanged via jwt-bearer. */
  assertion?: string;
  /** Current access token and its expiry (epoch seconds), if exchanged. */
  accessToken?: string;
  accessTokenExpiresAt?: number;
  /** Scopes granted at exchange time. */
  scopes?: string[];
  /** DID/handle learned during onboarding, for whoami. */
  did?: string;
  handle?: string;
  /** Set when the server told us this registration was revoked. */
  revoked?: boolean;
}

function credentialsFile(pdsUrl: string): string {
  const host = new URL(pdsUrl).host.replace(/[^a-zA-Z0-9.-]/g, '_');
  return path.join(stateDir(), `${host}.json`);
}

export function loadCredentials(pdsUrl: string): CachedCredentials | null {
  try {
    return JSON.parse(fs.readFileSync(credentialsFile(pdsUrl), 'utf8'));
  } catch (err: any) {
    if (err.code === 'ENOENT') return null;
    throw err;
  }
}

export function saveCredentials(creds: CachedCredentials): void {
  const file = credentialsFile(creds.pdsUrl);
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  const tmp = `${file}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(creds, null, 2) + '\n', { mode: 0o600 });
  fs.renameSync(tmp, file);
}

export function clearCredentials(pdsUrl: string): void {
  fs.rmSync(credentialsFile(pdsUrl), { force: true });
}
