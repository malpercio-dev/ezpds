// Test runner: the PDS refuses a non-https public_url (RFC 8414), so the
// suite fronts it with a loopback TLS proxy. The proxy's self-signed cert must
// be trusted by every Node process in the test (Node reads NODE_EXTRA_CA_CERTS
// only at startup), hence this wrapper: generate the throwaway cert, then
// re-spawn the actual `node --test` run with it trusted.

import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

const testDir = path.dirname(fileURLToPath(import.meta.url));
const tlsDir = fs.mkdtempSync(path.join(os.tmpdir(), 'custos-mcp-tls-'));
const keyFile = path.join(tlsDir, 'key.pem');
const certFile = path.join(tlsDir, 'cert.pem');

const openssl = spawnSync(
  'openssl',
  [
    'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256',
    '-keyout', keyFile, '-out', certFile, '-days', '7', '-nodes',
    '-subj', '/CN=custos-mcp-test',
    '-addext', 'subjectAltName=IP:127.0.0.1,DNS:localhost',
  ],
  { stdio: ['ignore', 'ignore', 'inherit'] },
);
if (openssl.status !== 0) {
  console.error('failed to generate the test TLS certificate (is openssl installed?)');
  process.exit(1);
}

const result = spawnSync(
  process.execPath,
  ['--test', path.join(testDir, 'conformance.test.ts')],
  {
    stdio: 'inherit',
    env: {
      ...process.env,
      NODE_EXTRA_CA_CERTS: certFile,
      CUSTOS_MCP_TEST_TLS_DIR: tlsDir,
    },
  },
);
fs.rmSync(tlsDir, { recursive: true, force: true });
process.exit(result.status ?? 1);
