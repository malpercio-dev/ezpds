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
  assert.equal(config.authServerOrigin, 'http://127.0.0.1:8080', 'AS defaults to the PDS origin locally');
});

test('AC2.7: the public authorization-server origin is distinct from the private PDS origin', () => {
  const config = loadConfig({
    MCP_SIDECAR_PDS_ORIGIN: 'http://pds.railway.internal:8080',
    MCP_SIDECAR_PUBLIC_ORIGIN: 'https://mcp.obsign.org',
    MCP_SIDECAR_AUTH_SERVER_ORIGIN: 'https://obsign.org',
  } as NodeJS.ProcessEnv);
  assert.equal(config.authServerOrigin, 'https://obsign.org');
  assert.notEqual(config.authServerOrigin, config.pdsOrigin, 'never the private forwarding address');
});

test('AC2.7: a malformed PDS origin is rejected', () => {
  assert.throws(
    () => loadConfig({ MCP_SIDECAR_PDS_ORIGIN: 'not a url' } as NodeJS.ProcessEnv),
    /not a valid URL/,
  );
});

test('AC2.7: a scheme-less origin fails loudly at startup, not on the first forwarded call', () => {
  // `new URL('pds.railway.internal:8080')` PARSES — the host becomes the scheme —
  // so without an explicit http(s) check this Railway-dashboard mistake only
  // surfaces later as an illegible "unknown scheme" fetch failure (found live
  // on staging during MM-370's HV-2 pass).
  assert.throws(
    () => loadConfig({ MCP_SIDECAR_PDS_ORIGIN: 'pds.railway.internal:8080' } as NodeJS.ProcessEnv),
    /must be an http:\/\/ or https:\/\/ URL/,
  );
  assert.throws(
    () =>
      loadConfig({
        MCP_SIDECAR_PDS_ORIGIN: 'http://pds.railway.internal:8080',
        MCP_SIDECAR_PUBLIC_ORIGIN: 'mcp.obsign.org:443',
      } as NodeJS.ProcessEnv),
    /MCP_SIDECAR_PUBLIC_ORIGIN must be an http:\/\/ or https:\/\/ URL/,
  );
  assert.throws(
    () =>
      loadConfig({
        MCP_SIDECAR_PDS_ORIGIN: 'http://pds.railway.internal:8080',
        MCP_SIDECAR_AUTH_SERVER_ORIGIN: 'obsign.org:443',
      } as NodeJS.ProcessEnv),
    /MCP_SIDECAR_AUTH_SERVER_ORIGIN must be an http:\/\/ or https:\/\/ URL/,
  );
  // A scheme-less value with NO port doesn't even parse as a URL — also refused.
  assert.throws(
    () =>
      loadConfig({
        MCP_SIDECAR_PDS_ORIGIN: 'http://pds.railway.internal:8080',
        MCP_SIDECAR_PUBLIC_ORIGIN: 'mcp.obsign.org',
      } as NodeJS.ProcessEnv),
    /MCP_SIDECAR_PUBLIC_ORIGIN is not a valid URL/,
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
