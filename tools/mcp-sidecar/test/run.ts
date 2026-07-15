// Test runner for the sidecar suite. Unlike the stdio conformance suite, these
// scaffold-phase tests need no TLS proxy: the sidecar and the stub PDS are both
// plain-HTTP loopback services, so there is no cert to generate or trust. This
// wrapper just runs `node --test` over the suite with TypeScript stripping's
// experimental warning silenced.

import { spawnSync } from 'node:child_process';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

const testDir = path.dirname(fileURLToPath(import.meta.url));
const files = [
  'config.test.ts',
  'registry.test.ts',
  'redaction.test.ts',
  'transport.test.ts',
  'forwarding.test.ts',
  'sessions.test.ts',
].map((f) => path.join(testDir, f));

const result = spawnSync(process.execPath, ['--disable-warning=ExperimentalWarning', '--test', ...files], {
  stdio: 'inherit',
  env: process.env,
});
process.exit(result.status ?? 1);
