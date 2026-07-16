// E2E runner (`pnpm test:e2e`): unlike the scaffold suite this spawns the real
// pds binary via tools/mcp's harness, which refuses a non-https public_url — so,
// exactly like tools/mcp/test/run.ts, generate a throwaway TLS cert and re-spawn
// `node --test` with it trusted (Node reads NODE_EXTRA_CA_CERTS only at
// startup). Needs a built `pds` (`cargo build -p pds`, or CUSTOS_MCP_TEST_PDS_BIN)
// plus tools/mcp + tools/mcp-sidecar deps installed; the node-only CI lane
// (mcp-check.yml) runs the scaffold suite only.

import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

const testDir = path.dirname(fileURLToPath(import.meta.url));
const files = ['create_post.test.ts', 'scope.test.ts', 'revocation.test.ts'].map((f) =>
  path.join(testDir, f),
);

const tlsDir = fs.mkdtempSync(path.join(os.tmpdir(), 'custos-sidecar-tls-'));
const keyFile = path.join(tlsDir, 'key.pem');
const certFile = path.join(tlsDir, 'cert.pem');

// The throwaway TLS dir is removed on every exit path (openssl failure
// included), so the exit code is decided inside try and applied after finally.
let status = 1;
try {
  const openssl = spawnSync(
    'openssl',
    [
      'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256',
      '-keyout', keyFile, '-out', certFile, '-days', '7', '-nodes',
      '-subj', '/CN=custos-mcp-sidecar-e2e',
      '-addext', 'subjectAltName=IP:127.0.0.1,DNS:localhost',
    ],
    { stdio: ['ignore', 'ignore', 'inherit'] },
  );
  if (openssl.status !== 0) {
    console.error('failed to generate the test TLS certificate (is openssl installed?)');
  } else {
    const result = spawnSync(
      process.execPath,
      ['--disable-warning=ExperimentalWarning', '--test', ...files],
      {
        stdio: 'inherit',
        env: {
          ...process.env,
          NODE_EXTRA_CA_CERTS: certFile,
          CUSTOS_MCP_TEST_TLS_DIR: tlsDir,
        },
      },
    );
    status = result.status ?? 1;
  }
} finally {
  fs.rmSync(tlsDir, { recursive: true, force: true });
}
process.exit(status);
