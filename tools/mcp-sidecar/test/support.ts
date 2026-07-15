// Shared test scaffolding for the sidecar suite. The scaffold-phase tests do not
// need the full hermetic PDS the stdio conformance suite spawns — forwarding is
// asserted against a lightweight stub PDS that records the inbound requests
// (headers included), which is exactly what the credential-forwarding ACs call
// for (AC2.5). The real firehose / real OAuth handshake is Phase 3 (MM-370) and
// the live checks (HV-2/HV-3).

import * as http from 'node:http';
import type { AddressInfo } from 'node:net';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { createSidecar } from '../src/server.ts';
import { loadConfig } from '../src/config.ts';
import type { SessionRegistry } from '../src/registry.ts';
import { callerSubject } from '../src/session.ts';

/** Re-exported so tests can derive the registry key for a token. */
export const callerSubjectOf = callerSubject;

/** A recorded inbound request to the stub PDS. */
export interface CapturedRequest {
  method: string;
  path: string;
  authorization: string | undefined;
  body: string;
}

export interface StubPds {
  url: string;
  requests: CapturedRequest[];
  /** Force the next XRPC response (status + JSON body). Defaults to 200 + `{}`. */
  respondWith: (status: number, body: unknown) => void;
  close: () => Promise<void>;
}

/** A stub PDS that records every request and returns a canned XRPC response. */
export function startStubPds(): Promise<StubPds> {
  const requests: CapturedRequest[] = [];
  let nextStatus = 200;
  let nextBody: unknown = {};

  return new Promise((resolve) => {
    const server = http.createServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on('data', (c) => chunks.push(c as Buffer));
      req.on('end', () => {
        requests.push({
          method: req.method ?? '',
          path: req.url ?? '',
          authorization: req.headers['authorization'],
          body: Buffer.concat(chunks).toString('utf8'),
        });
        res.writeHead(nextStatus, { 'content-type': 'application/json' });
        res.end(JSON.stringify(nextBody));
        // Reset to the default after each response so one override is one-shot.
        nextStatus = 200;
        nextBody = {};
      });
    });
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address() as AddressInfo;
      resolve({
        url: `http://127.0.0.1:${port}`,
        requests,
        respondWith: (status, body) => {
          nextStatus = status;
          nextBody = body;
        },
        close: () => new Promise((r) => server.close(() => r())),
      });
    });
  });
}

export interface RunningSidecar {
  url: string;
  registry: SessionRegistry;
  close: () => Promise<void>;
}

/** Build + listen the sidecar against a given PDS origin on an ephemeral port. */
export function startSidecar(env: Record<string, string>): Promise<RunningSidecar> {
  // Config parses with its default port; the test listens on an OS-assigned
  // ephemeral port instead (server.listen(0) below), so config.port is unused.
  const config = loadConfig(env as NodeJS.ProcessEnv);
  const { server, registry } = createSidecar(config);
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address() as AddressInfo;
      resolve({
        url: `http://127.0.0.1:${port}`,
        registry,
        close: () => new Promise((r) => server.close(() => r())),
      });
    });
  });
}

/** Connect an MCP client over Streamable HTTP, optionally forwarding a token. */
export async function connectClient(sidecarUrl: string, token?: string): Promise<Client> {
  const client = new Client({ name: 'sidecar-test', version: '0.0.0' });
  const transport = new StreamableHTTPClientTransport(new URL(`${sidecarUrl}/mcp`), {
    requestInit: token ? { headers: { Authorization: `Bearer ${token}` } } : undefined,
  });
  await client.connect(transport);
  return client;
}

/**
 * A syntactically valid, unsigned JWT with the given claims. `decodeJwtPayload`
 * reads the payload without verifying (the sidecar never verifies — the PDS is
 * the resource server), so this is enough to exercise DID/scope derivation and
 * forwarding. Never a real credential.
 */
export function fakeToken(claims: Record<string, unknown>): string {
  const b64 = (obj: unknown) => Buffer.from(JSON.stringify(obj)).toString('base64url');
  // A realistic-length signature segment so the token has the shape of a real
  // JWT (the redaction backstop matches JWT-shaped substrings).
  const signature = Buffer.from('sidecar-test-signature-placeholder').toString('base64url');
  return `${b64({ alg: 'ES256', typ: 'JWT' })}.${b64(claims)}.${signature}`;
}

export function toolJson(result: unknown): any {
  const content = (result as { content: { type: string; text: string }[] }).content;
  return JSON.parse(content[0]!.text);
}
