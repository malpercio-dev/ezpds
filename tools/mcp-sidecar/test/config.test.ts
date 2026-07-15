// AC2.7 — deployable as a third Railway service over private networking: the
// sidecar reads its PDS origin (a *.railway.internal private URL in the
// co-located tier) and its own public origin from config, and parse-fails loudly
// when the PDS origin is unset (no silent default to a public URL).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { loadConfig } from '../src/config.ts';

test('AC2.7: an unset PDS origin is rejected, not defaulted', () => {
  assert.throws(() => loadConfig({} as NodeJS.ProcessEnv), /MCP_SIDECAR_PDS_ORIGIN is not set/);
  assert.throws(
    () => loadConfig({ MCP_SIDECAR_PDS_ORIGIN: '   ' } as NodeJS.ProcessEnv),
    /MCP_SIDECAR_PDS_ORIGIN is not set/,
  );
});

test('AC2.7: a private PDS origin + public origin pair parses', () => {
  const config = loadConfig({
    MCP_SIDECAR_PDS_ORIGIN: 'http://pds.railway.internal:8080/',
    MCP_SIDECAR_PUBLIC_ORIGIN: 'https://mcp.obsign.org/',
    PORT: '3000',
  } as NodeJS.ProcessEnv);
  assert.equal(config.pdsOrigin, 'http://pds.railway.internal:8080');
  assert.equal(config.publicOrigin, 'https://mcp.obsign.org');
  assert.equal(config.port, 3000);
  assert.equal(config.mcpPath, '/mcp');
});

test('AC2.7: public origin defaults to the PDS origin for local single-host runs', () => {
  const config = loadConfig({
    MCP_SIDECAR_PDS_ORIGIN: 'http://127.0.0.1:8080',
  } as NodeJS.ProcessEnv);
  assert.equal(config.publicOrigin, 'http://127.0.0.1:8080');
});

test('AC2.7: a malformed PDS origin is rejected', () => {
  assert.throws(
    () => loadConfig({ MCP_SIDECAR_PDS_ORIGIN: 'not a url' } as NodeJS.ProcessEnv),
    /not a valid URL/,
  );
});

test('AC2.7: a non-numeric port is rejected', () => {
  assert.throws(
    () =>
      loadConfig({
        MCP_SIDECAR_PDS_ORIGIN: 'http://pds.railway.internal:8080',
        PORT: 'abc',
      } as NodeJS.ProcessEnv),
    /PORT must be a valid TCP port/,
  );
});
