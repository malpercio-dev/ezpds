// A local Custos for the cross-host Spaces scenario: the debug `pds` binary behind a TLS
// proxy on `https://localhost:<port>`, registering DIDs with the reference network's PLC.
//
//   node custos-local.mjs <repo-root> <plc-url> <tls-port> <dir>
//
// `<dir>` must hold `cert.pem`/`key.pem` for localhost; the reference trusts the same cert
// through NODE_EXTRA_CA_CERTS, which is how it reaches this host over https. Custos needs an
// https public URL, and the reference fetches it like any other PDS. The debug build reaches
// the reference's http loopback PDSes only because of EZPDS_DEV_ALLOW_LOOPBACK_TARGETS, which
// a release build ignores. Prints `CUSTOS <url>`, `ADMIN <token>`, then `ready`.

import { spawn } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { freePort, pdsBinary, startTlsProxy } from '../src/hermetic-pds.js';

const [repoRoot, plcUrl, portArg, dir] = process.argv.slice(2);
if (!repoRoot || !plcUrl || !portArg || !dir) {
  console.error('usage: custos-local.mjs <repo-root> <plc-url> <tls-port> <dir>');
  process.exit(2);
}
const ADMIN_TOKEN = 'interop-admin-token';
const url = `https://localhost:${portArg}`;
const tls = { key: fs.readFileSync(path.join(dir, 'key.pem')), cert: fs.readFileSync(path.join(dir, 'cert.pem')) };

const httpPort = await freePort();
const proxy = await startTlsProxy(tls, { port: Number(portArg), upstreamPort: httpPort });
fs.mkdirSync(path.join(dir, 'custos'), { recursive: true });

const proc = spawn(pdsBinary(repoRoot, process.env.EZPDS_HARNESS_PDS_BIN), [], {
  cwd: dir,
  // A closed env, as scripts/harness-pds.mjs keeps: no egress proxy, no stray EZPDS_* settings.
  env: {
    PATH: process.env.PATH ?? '',
    EZPDS_DATA_DIR: path.join(dir, 'custos'),
    EZPDS_DATABASE_URL: path.join(dir, 'custos', 'pds.db'),
    EZPDS_BIND_ADDRESS: '127.0.0.1',
    EZPDS_PORT: String(httpPort),
    EZPDS_PUBLIC_URL: url,
    EZPDS_AVAILABLE_USER_DOMAINS: 'localhost',
    EZPDS_ADMIN_TOKEN: ADMIN_TOKEN,
    EZPDS_PLC_DIRECTORY_URL: plcUrl,
    EZPDS_SIGNING_KEY_MASTER_KEY: '00'.repeat(32),
    EZPDS_SPACES_ENABLED: 'true',
    EZPDS_RATE_LIMIT_ENABLED: 'false',
    EZPDS_INVITE_CODE_REQUIRED: 'false',
    EZPDS_DEV_ALLOW_LOOPBACK_TARGETS: 'true',
    RUST_LOG: process.env.RUST_LOG ?? 'info',
  },
  stdio: ['ignore', 'inherit', 'inherit'],
});

const stop = () => { proc.kill(); proxy.close(); };
process.on('SIGINT', () => { stop(); process.exit(0); });
process.on('SIGTERM', () => { stop(); process.exit(0); });
proc.on('exit', (code) => { proxy.close(); console.error(`custos exited (${code})`); process.exit(code ?? 1); });

for (const deadline = Date.now() + 60_000; ;) {
  const ok = await fetch(`http://127.0.0.1:${httpPort}/xrpc/_health`).then((r) => r.ok, () => false);
  if (ok) break;
  if (Date.now() > deadline) { console.error('custos did not become healthy in 60s'); stop(); process.exit(1); }
  await new Promise((r) => setTimeout(r, 250));
}
console.log(`CUSTOS ${url}`);
console.log(`ADMIN ${ADMIN_TOKEN}`);
console.log('ready');
