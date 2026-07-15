// Sidecar configuration. Everything comes from the environment. Two origins are
// load-bearing and distinct:
//
//   MCP_SIDECAR_PDS_ORIGIN   — where the sidecar reaches the PDS. In the
//     co-located hosted tier this is a Railway *private* address
//     (`http://pds.railway.internal:PORT`), never the public domain; the
//     private network keeps forwarded traffic off the public internet.
//   MCP_SIDECAR_PUBLIC_ORIGIN — the sidecar's own public URL
//     (`https://mcp.obsign.org`), advertised as the OAuth *resource* identifier
//     in the MCP-spec protected-resource metadata.
//
// The PDS origin is required and parse-fails loudly: silently defaulting to a
// public URL would send forwarded credentials over the wrong path.

export interface SidecarConfig {
  /** Where the sidecar forwards XRPC calls to (private network in prod). */
  pdsOrigin: string;
  /**
   * The public Custos authorization-server origin advertised to MCP clients in
   * the protected-resource metadata. Distinct from `pdsOrigin`: the client
   * completes OAuth against this reachable public URL (`https://obsign.org`),
   * never the private `*.railway.internal` address the sidecar forwards to.
   */
  authServerOrigin: string;
  /** The sidecar's own public origin — the OAuth resource identifier. */
  publicOrigin: string;
  /** TCP port to listen on. Railway injects PORT; default 8080 for local runs. */
  port: number;
  /** MCP endpoint path. */
  mcpPath: string;
}

function trimTrailingSlash(url: string): string {
  return url.replace(/\/+$/, '');
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
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error(`${name} is not a valid URL: ${JSON.stringify(value)}`);
  }
  return trimTrailingSlash(parsed.toString());
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
    ? trimTrailingSlash(new URL(publicOriginRaw).toString())
    : pdsOrigin;

  // The authorization server clients reach is Custos's PUBLIC URL, never the
  // private forwarding address. It defaults to the PDS origin only when that
  // origin is already public (local single-host runs); a co-located deployment
  // whose PDS origin is `*.railway.internal` MUST set this to `https://obsign.org`.
  const authServerRaw = env.MCP_SIDECAR_AUTH_SERVER_ORIGIN?.trim();
  const authServerOrigin = authServerRaw
    ? trimTrailingSlash(new URL(authServerRaw).toString())
    : pdsOrigin;

  const rawPort = env.PORT ?? env.MCP_SIDECAR_PORT;
  const port = rawPort ? Number(rawPort) : 8080;
  if (!Number.isInteger(port) || port <= 0 || port > 65535) {
    throw new Error(`PORT must be a valid TCP port, got ${JSON.stringify(rawPort)}`);
  }

  return {
    pdsOrigin,
    authServerOrigin,
    publicOrigin,
    port,
    mcpPath: env.MCP_SIDECAR_PATH ?? '/mcp',
  };
}
