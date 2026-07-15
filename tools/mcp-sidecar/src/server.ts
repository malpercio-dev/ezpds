// Credential-forwarding Streamable-HTTP MCP sidecar.
//
// Same tool surface as the stdio server (imported, not forked, from ezpds-mcp),
// but served over HTTP and multi-caller. Each caller authenticates via OAuth
// against Custos (the sidecar is the MCP-spec resource server; Custos is the
// authorization server, ADR-0019); the caller's bearer rides each tool call to
// the PDS and nothing durable is cached (ADR-0024). The sidecar terminates only
// the transport + the OAuth resource metadata; all auth decisions stay in the
// PDS.

import * as http from 'node:http';
import { randomUUID } from 'node:crypto';
import { realpathSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { isInitializeRequest } from '@modelcontextprotocol/sdk/types.js';
import type { AuthInfo } from '@modelcontextprotocol/sdk/server/auth/types.js';
// The tool surface is single-sourced from the sibling stdio package. It is
// imported by relative path (not the `ezpds-mcp` package specifier) because both
// packages run TypeScript natively with no build step, and Node refuses to
// type-strip files resolved under `node_modules` — a package-specifier import of
// this `.ts` source would fail at runtime. The relative path reaches the real
// sibling directory, so a tool bugfix still lands once.
import { registerTools } from '../../mcp/src/tools.ts';
import { decodeJwtPayload } from '../../mcp/src/auth.ts';
import { loadConfig, type SidecarConfig } from './config.ts';
import { SessionRegistry } from './registry.ts';
import { callerSubject } from './session.ts';
import { log, redactError } from './log.ts';

/** Thrown when a tool is invoked without an authenticated caller. */
export class UnauthenticatedError extends Error {
  constructor() {
    super(
      'This request is not authenticated. The hosted MCP sidecar forwards your own ' +
        'credential — complete the OAuth authorization against Custos and present a ' +
        'bearer token; the sidecar holds none on your behalf.',
    );
  }
}

/**
 * Build an `AuthInfo` from a request's `Authorization: Bearer` header, or
 * `undefined` when there is none. The sidecar does not verify the token itself —
 * the PDS is the resource server and rejects an invalid token on the forwarded
 * call; here we only read the caller identity/scopes to key the session.
 */
export function authFromRequest(authorization: string | undefined): AuthInfo | undefined {
  if (!authorization) return undefined;
  const match = /^Bearer\s+(.+)$/i.exec(authorization.trim());
  if (!match) return undefined;
  const token = match[1]!.trim();
  if (!token) return undefined;

  let scopes: string[] = [];
  // Best-effort read of the token's scope claim, purely to key/annotate the
  // in-memory session; the authoritative scope check happens in the PDS.
  try {
    const scope = decodeJwtPayload(token).scope;
    if (typeof scope === 'string' && scope) scopes = scope.split(' ');
  } catch {
    // opaque token — leave scopes empty
  }
  return { token, clientId: callerSubject(token), scopes };
}

/** The MCP-spec protected-resource metadata pointing at Custos as the AS. */
function protectedResourceMetadata(config: SidecarConfig): Record<string, unknown> {
  return {
    resource: config.publicOrigin,
    // The client must reach the PUBLIC Custos URL, never the private forwarding
    // origin (which is unroutable from outside the Railway network).
    authorization_servers: [config.authServerOrigin],
  };
}

// MCP JSON-RPC messages are tiny; a generous ceiling still stops an
// unauthenticated client from streaming an unbounded body into memory.
const MAX_BODY_BYTES = 1024 * 1024;

// Bounds on the live-transport map: a hard cap plus idle expiry, so an
// abandoned MCP session cannot pin memory indefinitely.
const MAX_TRANSPORTS = 1024;
const TRANSPORT_IDLE_MS = 10 * 60_000;

/** Thrown by `readBody` when a request body exceeds `MAX_BODY_BYTES`. */
class PayloadTooLargeError extends Error {}

function readBody(req: http.IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let total = 0;
    let settled = false;
    req.on('data', (chunk: Buffer) => {
      if (settled) return;
      total += chunk.length;
      if (total > MAX_BODY_BYTES) {
        // Stop buffering immediately (memory stays bounded) and reject; the
        // caller sends 413. We do NOT destroy the socket here — that would reset
        // the connection before the 413 response can flush.
        settled = true;
        chunks.length = 0;
        reject(new PayloadTooLargeError());
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      if (!settled) {
        settled = true;
        resolve(Buffer.concat(chunks).toString('utf8'));
      }
    });
    req.on('error', (err) => {
      if (!settled) {
        settled = true;
        reject(err);
      }
    });
  });
}

function sendJson(res: http.ServerResponse, status: number, body: unknown): void {
  const payload = JSON.stringify(body);
  res.writeHead(status, { 'content-type': 'application/json' });
  res.end(payload);
}

/**
 * Build the HTTP server around a fresh session registry. Returns the server and
 * the registry so tests can drive both; nothing is bound to a listening socket
 * until the caller calls `listen`.
 */
export function createSidecar(config: SidecarConfig): {
  server: http.Server;
  registry: SessionRegistry;
} {
  const registry = new SessionRegistry({ pdsOrigin: config.pdsOrigin });

  // One transport (and MCP server) per live MCP session, keyed by the session
  // id the transport assigns on initialize. Bounded and idle-expired so an
  // abandoned client (one that never sends DELETE) cannot grow the map without
  // limit. All transports share the one registry.
  const transports = new Map<string, { transport: StreamableHTTPServerTransport; lastActivity: number }>();

  function sweepIdleTransports(now: number): void {
    for (const [id, entry] of transports) {
      if (now - entry.lastActivity > TRANSPORT_IDLE_MS) {
        transports.delete(id);
        void entry.transport.close();
      }
    }
  }

  function touch(id: string, now: number): void {
    const entry = transports.get(id);
    if (entry) entry.lastActivity = now;
  }

  function newTransport(): StreamableHTTPServerTransport {
    const transport: StreamableHTTPServerTransport = new StreamableHTTPServerTransport({
      sessionIdGenerator: () => randomUUID(),
      enableJsonResponse: true,
      onsessioninitialized: (id) => {
        transports.set(id, { transport, lastActivity: Date.now() });
      },
    });
    transport.onclose = () => {
      if (transport.sessionId) transports.delete(transport.sessionId);
    };
    const mcp = new McpServer({ name: 'custos-mcp-sidecar', version: '0.1.0' });
    registerTools(mcp, (extra) => {
      const session = registry.resolve(extra?.authInfo);
      if (!session) throw new UnauthenticatedError();
      return session;
    });
    void mcp.connect(transport);
    return transport;
  }

  const server = http.createServer((req, res) => {
    void handle(req, res).catch((err) => {
      log(`unhandled request error: ${redactError(err)}`);
      if (!res.headersSent) sendJson(res, 500, { error: 'internal error' });
    });
  });

  async function handle(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    const url = new URL(req.url ?? '/', config.publicOrigin);

    if (req.method === 'GET' && url.pathname === '/.well-known/oauth-protected-resource') {
      sendJson(res, 200, protectedResourceMetadata(config));
      return;
    }
    if (req.method === 'GET' && (url.pathname === '/' || url.pathname === '/healthz')) {
      sendJson(res, 200, { status: 'ok' });
      return;
    }
    if (url.pathname !== config.mcpPath) {
      sendJson(res, 404, { error: 'not found' });
      return;
    }

    // Attach the caller's forwarded credential so the transport threads it into
    // each tool call's `extra.authInfo`. It is bound per request only — the
    // registry mints a fresh, request-scoped session and stores no credential.
    const auth = authFromRequest(req.headers['authorization']);
    (req as http.IncomingMessage & { auth?: AuthInfo }).auth = auth;

    const now = Date.now();
    sweepIdleTransports(now);
    const sessionId = req.headers['mcp-session-id'];
    const existing = typeof sessionId === 'string' ? transports.get(sessionId)?.transport : undefined;
    if (typeof sessionId === 'string') touch(sessionId, now);

    if (req.method === 'POST') {
      let raw: string;
      try {
        raw = await readBody(req);
      } catch (err) {
        if (err instanceof PayloadTooLargeError) {
          sendJson(res, 413, { error: 'request body too large' });
          return;
        }
        throw err;
      }
      let body: unknown;
      try {
        body = raw ? JSON.parse(raw) : undefined;
      } catch {
        sendJson(res, 400, { error: 'invalid JSON body' });
        return;
      }
      if (!existing && isInitializeRequest(body) && transports.size >= MAX_TRANSPORTS) {
        // At capacity: refuse new sessions rather than allocate past the bound.
        sendJson(res, 503, { error: 'sidecar at session capacity; retry shortly' });
        return;
      }
      const transport = existing ?? (isInitializeRequest(body) ? newTransport() : undefined);
      if (!transport) {
        sendJson(res, 400, { error: 'no valid MCP session; send an initialize request first' });
        return;
      }
      await transport.handleRequest(req, res, body);
      return;
    }

    // GET (SSE stream) and DELETE (session teardown) require an existing session.
    if (!existing) {
      sendJson(res, 400, { error: 'unknown or missing MCP session id' });
      return;
    }
    await existing.handleRequest(req, res);
  }

  return { server, registry };
}

/**
 * True when this module is the process entry point. Compares realpaths so it
 * holds whether launched as `node src/server.ts` (relative argv), through the
 * bin wrapper (a `..`-containing path), or via an absolute path — not just the
 * exact-string form.
 */
function isMain(): boolean {
  const entry = process.argv[1];
  if (!entry) return false;
  try {
    return realpathSync(entry) === fileURLToPath(import.meta.url);
  } catch {
    return false;
  }
}

// Entry point: bind the socket. Skipped when imported by tests (which call
// createSidecar directly and listen on an ephemeral port).
if (isMain()) {
  const config = loadConfig();
  const { server } = createSidecar(config);
  server.listen(config.port, () => {
    log(`listening on :${config.port}${config.mcpPath} — forwarding to ${config.pdsOrigin}`);
    log(`resource identifier: ${config.publicOrigin}`);
  });
}
