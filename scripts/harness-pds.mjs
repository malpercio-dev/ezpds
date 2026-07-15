#!/usr/bin/env node
/**
 * Hermetic local PDS for the browser test harness's proxy mode
 * (browser-harness.AC3.4).
 *
 * Adapts tools/mcp/test/harness.ts: spawns the locally-built `pds` binary configured
 * entirely from env vars, fronted by a mock plc.directory (no live-network traffic) and a
 * throwaway admin token. The PDS requires an https public_url (RFC 8414 for the OAuth
 * issuer), so — like the MCP harness — it is fronted by a TLS-terminating loopback proxy
 * using a throwaway self-signed cert. The vite dev server proxies same-origin `/__pds/*`
 * to this https origin with `secure: false`, so the browser makes no cross-origin request
 * and no CORS changes land in the PDS.
 *
 * Prints the base URL, admin token, and the exact env line to configure a
 * `dev:harness:proxy` server, then runs until Ctrl-C, cleaning up process and temp data.
 *
 * Usage: `just harness-pds`. Requires a built pds binary (`cargo build -p pds`) or
 * `EZPDS_HARNESS_PDS_BIN`; `openssl` and `node` come from the dev shell.
 */
import { execFileSync, spawn } from 'node:child_process';
import * as fs from 'node:fs';
import * as http from 'node:http';
import * as https from 'node:https';
import * as net from 'node:net';
import * as os from 'node:os';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

const TLS_PORT = Number(process.env.EZPDS_HARNESS_PDS_PORT ?? 8091);
const ADMIN_TOKEN = process.env.EZPDS_HARNESS_ADMIN_TOKEN ?? 'harness-admin-token';
const BASE_URL = `https://localhost:${TLS_PORT}`;

function pdsBinary() {
  const explicit = process.env.EZPDS_HARNESS_PDS_BIN;
  const candidates = explicit
    ? [explicit]
    : [path.join(repoRoot, 'target', 'debug', 'pds'), path.join(repoRoot, 'target', 'release', 'pds')];
  for (const candidate of candidates) {
    if (fs.existsSync(candidate)) return candidate;
  }
  console.error(
    `\n[harness-pds] no pds binary found (looked at:\n  ${candidates.join('\n  ')}\n).\n` +
      'Build it first: `cargo build -p pds`, or set EZPDS_HARNESS_PDS_BIN.\n'
  );
  process.exit(1);
}

/** Generate a throwaway self-signed cert for localhost via openssl. */
function generateCert(dir) {
  const keyPath = path.join(dir, 'key.pem');
  const certPath = path.join(dir, 'cert.pem');
  execFileSync(
    'openssl',
    [
      'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
      '-keyout', keyPath,
      '-out', certPath,
      '-days', '1',
      '-subj', '/CN=localhost',
      '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1',
    ],
    { stdio: 'ignore' }
  );
  return { key: fs.readFileSync(keyPath), cert: fs.readFileSync(certPath) };
}

/** An OS-assigned free port. */
function freePort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      server.close((err) => (err ? reject(err) : resolve(port)));
    });
  });
}

/** A stub plc.directory that accepts every op — never touch the real one from the harness. */
function startMockPlc() {
  return new Promise((resolve) => {
    const server = http.createServer((_req, res) => {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end('{}');
    });
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      resolve({ url: `http://127.0.0.1:${port}`, close: () => server.close() });
    });
  });
}

/** TLS-terminating loopback proxy in front of a plain-http upstream (the pds). */
function startTlsProxy(tls, upstreamPort) {
  return new Promise((resolve) => {
    const server = https.createServer(tls, (req, res) => {
      const upstream = http.request(
        { host: '127.0.0.1', port: upstreamPort, path: req.url, method: req.method, headers: req.headers },
        (upstreamRes) => {
          res.writeHead(upstreamRes.statusCode ?? 502, upstreamRes.headers);
          upstreamRes.pipe(res);
        }
      );
      upstream.on('error', (err) => {
        res.writeHead(502, { 'content-type': 'text/plain' });
        res.end(`proxy error: ${err.message}`);
      });
      req.pipe(upstream);
    });
    server.listen(TLS_PORT, '127.0.0.1', () => resolve({ close: () => server.close() }));
  });
}

async function waitHealthy(httpPort, deadlineMs) {
  const deadline = Date.now() + deadlineMs;
  for (;;) {
    try {
      const res = await fetch(`http://127.0.0.1:${httpPort}/xrpc/_health`, {
        signal: AbortSignal.timeout(2000),
      });
      if (res.ok) return;
    } catch {
      // not up yet
    }
    if (Date.now() > deadline) throw new Error('pds did not become healthy in time');
    await new Promise((r) => setTimeout(r, 200));
  }
}

const bin = pdsBinary();
const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ezpds-harness-pds-'));
fs.mkdirSync(path.join(dataDir, 'data'), { recursive: true });

const tls = generateCert(dataDir);
const plc = await startMockPlc();
const httpPort = await freePort();
const proxy = await startTlsProxy(tls, httpPort);

const proc = spawn(bin, [], {
  cwd: dataDir,
  env: {
    PATH: process.env.PATH ?? '',
    EZPDS_DATA_DIR: path.join(dataDir, 'data'),
    EZPDS_DATABASE_URL: path.join(dataDir, 'data', 'pds.db'),
    EZPDS_BIND_ADDRESS: '127.0.0.1',
    EZPDS_PORT: String(httpPort),
    EZPDS_PUBLIC_URL: BASE_URL,
    EZPDS_AVAILABLE_USER_DOMAINS: 'localhost',
    EZPDS_ADMIN_TOKEN: ADMIN_TOKEN,
    EZPDS_PLC_DIRECTORY_URL: plc.url,
    // Throwaway: encrypts per-account repo signing keys in the ephemeral DB.
    EZPDS_SIGNING_KEY_MASTER_KEY: '00'.repeat(32),
    EZPDS_RATE_LIMIT_ENABLED: 'false',
    EZPDS_AGENT_AUTH_SERVICE_AUTH_ENABLED: 'true',
  },
  stdio: ['ignore', 'inherit', 'inherit'],
});

let shuttingDown = false;
function shutdown(code) {
  if (shuttingDown) return;
  shuttingDown = true;
  try { proc.kill(); } catch { /* already gone */ }
  proxy.close();
  plc.close();
  try { fs.rmSync(dataDir, { recursive: true, force: true }); } catch { /* best effort */ }
  process.exit(code ?? 0);
}
process.on('SIGINT', () => shutdown(0));
process.on('SIGTERM', () => shutdown(0));
proc.on('exit', (code) => {
  if (!shuttingDown) {
    console.error(`\n[harness-pds] pds exited unexpectedly (code ${code}).`);
    shutdown(code ?? 1);
  }
});

try {
  await waitHealthy(httpPort, 30_000);
} catch (err) {
  console.error(`[harness-pds] ${err.message}`);
  shutdown(1);
}

console.log(`
[harness-pds] hermetic PDS ready.

  Base URL:      ${BASE_URL}   (self-signed TLS; vite proxies with secure:false)
  Admin token:   ${ADMIN_TOKEN}
  plc.directory: mocked (${plc.url}) — no live-network traffic

Point a harness dev server at it (in another terminal):

  VITE_HARNESS_PDS_URL=${BASE_URL} VITE_HARNESS_ADMIN_TOKEN=${ADMIN_TOKEN} \\
    pnpm --dir apps/identity-wallet dev:harness:proxy
  VITE_HARNESS_PDS_URL=${BASE_URL} VITE_HARNESS_ADMIN_TOKEN=${ADMIN_TOKEN} \\
    pnpm --dir apps/admin-companion dev:harness:proxy

The dev server proxies same-origin /__pds/* to this PDS (no CORS changes here).
Press Ctrl-C to stop and wipe the ephemeral data dir.
`);
