// Central configuration for the Custos MCP server. Everything comes from the
// environment (MCP clients pass env via their server config block); the PDS URL
// is the only required setting.

import * as os from 'node:os';
import * as path from 'node:path';

function requireEnv(name: string): string {
  const value = process.env[name];
  if (!value) {
    throw new Error(
      `${name} is not set. Configure it in your MCP client's server config ` +
        `(see tools/mcp/README.md) — e.g. ${name}=https://your-pds.example.com`,
    );
  }
  return value;
}

/** Base URL of the Custos PDS this server onboards to. Required. */
export function pdsUrl(): string {
  return requireEnv('CUSTOS_PDS_URL').replace(/\/+$/, '');
}

/**
 * Email used as `login_hint` for service_auth registration. Required for
 * first-run onboarding; once a token is cached it is only needed again after
 * revocation.
 */
export function loginEmail(): string | null {
  return process.env.CUSTOS_MCP_EMAIL ?? null;
}

/** Human-readable agent name sent with registration and shown in the wallet. */
export const AGENT_NAME = process.env.CUSTOS_MCP_AGENT_NAME ?? 'Custos MCP';

/**
 * Destructive tools (put_record, delete_record) are off unless this is set to
 * "1" or "true" — with it unset they are not even listed.
 */
export const ALLOW_DESTRUCTIVE = ['1', 'true'].includes(
  (process.env.CUSTOS_MCP_ALLOW_DESTRUCTIVE ?? '').toLowerCase(),
);

// Pacing: minimum gap between HTTP requests so tool-call bursts stay far below
// the PDS per-IP limits. Same discipline as tools/interop.
export const MIN_REQUEST_INTERVAL_MS = Number(process.env.CUSTOS_MCP_PACE_MS ?? 150);

// How many times to retry a 429 (honoring Retry-After) before giving up.
export const MAX_RATE_LIMIT_RETRIES = 4;

/**
 * Where cached credentials live: an OS-appropriate per-user state directory,
 * overridable for tests. Files are written 0600.
 */
export function stateDir(): string {
  if (process.env.CUSTOS_MCP_STATE_DIR) return process.env.CUSTOS_MCP_STATE_DIR;
  if (process.platform === 'darwin') {
    return path.join(os.homedir(), 'Library', 'Application Support', 'custos-mcp');
  }
  const xdg = process.env.XDG_STATE_HOME ?? path.join(os.homedir(), '.local', 'state');
  return path.join(xdg, 'custos-mcp');
}
