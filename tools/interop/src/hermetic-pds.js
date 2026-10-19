// Shared primitives for spawning a hermetic local PDS: locating the built binary, an
// OS-assigned free loopback port, a stub plc.directory, and a TLS-terminating loopback
// proxy in front of a plain-http upstream. Used by scripts/harness-pds.mjs (the browser
// test harness's proxy mode) and tools/mcp/test/harness.ts (the MCP + OAuth conformance
// suites), which each spawn their own hermetic PDS instance with different env/cert
// strategy but the same underlying plumbing.
//
// Plain node builtins only — no npm dependencies — so scripts/harness-pds.mjs can import
// this by relative path without a `pnpm install` in tools/interop.
import * as fs from 'node:fs';
import * as http from 'node:http';
import * as https from 'node:https';
import * as net from 'node:net';
import * as path from 'node:path';

/** Locate a built pds binary: `explicit` if given, else target/{debug,release}/pds under `repoRoot`. */
export function pdsBinary(repoRoot, explicit) {
  const candidates = explicit
    ? [explicit]
    : [path.join(repoRoot, 'target', 'debug', 'pds'), path.join(repoRoot, 'target', 'release', 'pds')];
  for (const candidate of candidates) {
    if (fs.existsSync(candidate)) return candidate;
  }
  throw new Error(
    `no pds binary found (looked at ${candidates.join(', ')}). ` +
      'Run `cargo build -p pds` first, or point at one explicitly.',
  );
}

/** An OS-assigned free port (bind on 0, read, release) — no collision guessing. */
export function freePort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.listen(0, '127.0.0.1', () => {
      const port = server.address().port;
      server.close((err) => (err ? reject(err) : resolve(port)));
    });
  });
}

/** A stub plc.directory that accepts every op. Never touch the real one from tests. */
export function startMockPlc() {
  return new Promise((resolve) => {
    const server = http.createServer((_req, res) => {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end('{}');
    });
    server.listen(0, '127.0.0.1', () => {
      const port = server.address().port;
      resolve({ url: `http://127.0.0.1:${port}`, close: () => server.close() });
    });
  });
}

/**
 * TLS-terminating loopback proxy in front of a plain-http upstream (the pds).
 *
 * `port` defaults to 0 (OS-assigned); pass a fixed port to bind a stable, human-facing
 * address instead. `upstreamPort` may be set up front or later via the returned
 * `setUpstreamPort` (needed when the upstream's own port depends on the proxy already
 * having claimed its port, e.g. a public_url that must be known before the pds starts).
 */
export function startTlsProxy(tls, { port = 0, upstreamPort = 0 } = {}) {
  let currentUpstream = upstreamPort;
  return new Promise((resolve, reject) => {
    const server = https.createServer(tls, (req, res) => {
      const upstream = http.request(
        { host: '127.0.0.1', port: currentUpstream, path: req.url, method: req.method, headers: req.headers },
        (upstreamRes) => {
          res.writeHead(upstreamRes.statusCode ?? 502, upstreamRes.headers);
          upstreamRes.pipe(res);
        },
      );
      upstream.on('error', (err) => {
        res.writeHead(502, { 'content-type': 'text/plain' });
        res.end(`proxy error: ${err.message}`);
      });
      req.pipe(upstream);
    });
    server.on('error', (err) => {
      if (err.code === 'EADDRINUSE') {
        reject(new Error(`harness TLS port ${port} is already in use.`));
      } else {
        reject(err);
      }
    });
    server.listen(port, '127.0.0.1', () => {
      const boundPort = server.address().port;
      resolve({
        port: boundPort,
        setUpstreamPort: (p) => {
          currentUpstream = p;
        },
        close: () => server.close(),
      });
    });
  });
}
