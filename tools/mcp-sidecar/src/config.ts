// Sidecar configuration. Everything comes from the environment. Two origins are
// load-bearing and distinct:
//
//   MCP_SIDECAR_PDS_ORIGIN   — where the sidecar reaches the PDS. In the
//     co-located hosted tier this is a Railway *private* address
//     (`http://pds.railway.internal:PORT`), never the public domain; the
//     private network keeps forwarded traffic off the public internet.
//   MCP_SIDECAR_PUBLIC_ORIGIN — the sidecar's own public URL
//     (`https://mcp.obsign.org`). The OAuth *resource* identifier advertised in
//     the MCP-spec protected-resource metadata is this origin plus the MCP path
//     (`https://mcp.obsign.org/mcp`), and the PDS must list that exact value in
//     its `[oauth] connector_resources` or it refuses the connector's sign-in.
//
// The PDS origin is required and parse-fails loudly: silently defaulting to a
// public URL would send forwarded credentials over the wrong path.
//
// The public *authorization-server* origin is deliberately NOT configured here.
// It is read at runtime from the PDS's own RFC 8414 metadata (`issuer`), so the
// two can never disagree; see `server.ts`.

export interface SidecarConfig {
  /** Where the sidecar forwards XRPC calls to (private network in prod). */
  pdsOrigin: string;
  /** The sidecar's own public origin. */
  publicOrigin: string;
  /** The OAuth resource identifier: the public origin plus the MCP path. */
  resource: string;
  /** The scopes a connector should request, advertised as `scopes_supported`. */
  scopes: string[];
  /** TCP port to listen on. Railway injects PORT; default 8080 for local runs. */
  port: number;
  /** MCP endpoint path. */
  mcpPath: string;
}

// What a connector asks for when the operator sets nothing: the same reach as the
// PDS's default agent scope profile. An MCP client with no scope of its own
// requests exactly this list, so it is also what the user sees at consent. The
// `rpc` audience names the default AppView; an operator on another AppView, or
// one who wants Spaces tools to work, overrides the list with MCP_SIDECAR_SCOPES.
// The PDS drops anything above its connector ceiling whatever is listed here.
const DEFAULT_SCOPES = [
  'atproto',
  'repo:*?action=create&action=update',
  'repo:*?action=delete',
  'blob:*/*',
  'rpc:*?aud=did:web:api.bsky.app',
];

function trimTrailingSlash(url: string): string {
  return url.replace(/\/+$/, '');
}

/**
 * Parse an origin env value, requiring an http(s) scheme. A bare
 * `host.railway.internal:8080` (the natural Railway-dashboard mistake) is a
 * *valid* URL whose scheme is the hostname — it would sail through `new URL`
 * and only surface later as an illegible "unknown scheme" on the first
 * forwarded call, so it must be refused at startup instead.
 */
function parseHttpOrigin(name: string, value: string): string {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error(`${name} is not a valid URL: ${JSON.stringify(value)}`);
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new Error(
      `${name} must be an http:// or https:// URL, got ${JSON.stringify(value)} — ` +
        'a bare host:port is missing its scheme (e.g. http://pds.railway.internal:8080).',
    );
  }
  return trimTrailingSlash(parsed.toString());
}

function requireOrigin(env: NodeJS.ProcessEnv, name: string): string {
  const value = env[name];
  if (!value || !value.trim()) {
    throw new Error(
      `${name} is not set. The sidecar will not guess a PDS origin — in the ` +
        'co-located tier this is the PDS\'s private Railway address ' +
        '(e.g. http://pds.railway.internal:8080). See docs/deploy.md → "MCP sidecar".',
    );
  }
  return parseHttpOrigin(name, value);
}

/**
 * Parse the sidecar config from an environment. Exported (rather than reading
 * `process.env` at module scope) so tests can drive it with a hand-built env and
 * assert the fail-loud behavior without mutating the process.
 */
export function loadConfig(env: NodeJS.ProcessEnv = process.env): SidecarConfig {
  const pdsOrigin = requireOrigin(env, 'MCP_SIDECAR_PDS_ORIGIN');
  // The public origin defaults to the PDS origin only for local single-host
  // runs; a real deployment sets it to the sidecar's own domain.
  const publicOriginRaw = env.MCP_SIDECAR_PUBLIC_ORIGIN?.trim();
  const publicOrigin = publicOriginRaw
    ? parseHttpOrigin('MCP_SIDECAR_PUBLIC_ORIGIN', publicOriginRaw)
    : pdsOrigin;

  const rawPort = env.PORT ?? env.MCP_SIDECAR_PORT;
  const port = rawPort ? Number(rawPort) : 8080;
  if (!Number.isInteger(port) || port <= 0 || port > 65535) {
    throw new Error(`PORT must be a valid TCP port, got ${JSON.stringify(rawPort)}`);
  }

  const mcpPath = env.MCP_SIDECAR_PATH ?? '/mcp';
  const scopes = env.MCP_SIDECAR_SCOPES?.trim().split(/\s+/).filter(Boolean) ?? [];
  if (scopes.length > 0 && !scopes.includes('atproto')) {
    throw new Error('MCP_SIDECAR_SCOPES must include "atproto" — the PDS refuses a request without it.');
  }

  return {
    pdsOrigin,
    publicOrigin,
    resource: `${publicOrigin}${mcpPath}`,
    scopes: scopes.length > 0 ? scopes : DEFAULT_SCOPES,
    port,
    mcpPath,
  };
}
