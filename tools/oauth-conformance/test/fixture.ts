// Per-suite fixture: a hermetic PDS plus an account that can drive the consent form.
//
// The PDS spawner, TLS proxy, mock plc.directory, and account ceremony are all reused from
// tools/mcp/test/harness.ts rather than duplicated — that module is already the second
// consumer's dependency (tools/mcp-sidecar imports it the same way), so this is an
// established seam rather than a new one.
//
// The one thing this fixture adds is the account's **password**. tools/mcp's `TestAccount`
// omits it (its suite authenticates with a session JWT), but the OAuth consent form needs a
// real credential, so provisioning is repeated here against interop's richer return value.

import * as fs from 'node:fs';
import * as http from 'node:http';
import * as net from 'node:net';
import * as os from 'node:os';
import * as path from 'node:path';

import { ADMIN_TOKEN, spawnPds, type SpawnedPds } from '../../mcp/test/harness.ts';
import { startMockPlc, type MockPlc } from './mock-plc.ts';

export { ADMIN_TOKEN };

/** An OS-assigned free port, so parallel test files never collide. */
function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.listen(0, '127.0.0.1', () => {
      const port = (server.address() as net.AddressInfo).port;
      server.close((err) => (err ? reject(err) : resolve(port)));
    });
  });
}

export interface ClientHost {
  clientId: string;
  redirectUri: string;
  close: () => void;
}

/**
 * Serve an OAuth client metadata document over plain-http loopback.
 *
 * The PDS resolves a URL-shaped `client_id` by fetching it, so a test client must actually be
 * published somewhere. Loopback is the spec's local-development exception and this server
 * accepts it (`auth/oauth_client_resolution.rs`: plain http is allowed for localhost /
 * 127.0.0.1 / ::1, and such clients are exempt from the reverse-FQDN redirect rule) — which
 * is what makes a hermetic third-party-client harness possible at all.
 */
export async function startClientHost(
  metadata: Record<string, unknown> = {},
): Promise<ClientHost> {
  const port = await freePort();
  const origin = `http://127.0.0.1:${port}`;
  const clientId = `${origin}/client-metadata.json`;
  const redirectUri = `${origin}/callback`;
  const document = {
    client_id: clientId,
    client_name: 'Custos OAuth conformance suite',
    redirect_uris: [redirectUri],
    grant_types: ['authorization_code', 'refresh_token'],
    response_types: ['code'],
    application_type: 'web',
    token_endpoint_auth_method: 'none',
    dpop_bound_access_tokens: true,
    scope: 'atproto transition:generic',
    ...metadata,
  };

  const server = http.createServer((req, res) => {
    if (req.url?.startsWith('/client-metadata.json')) {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify(document));
      return;
    }
    // The redirect target: nothing follows it (the suite reads the Location header
    // directly), but answering keeps a stray follow from hanging.
    res.writeHead(204);
    res.end();
  });
  await new Promise<void>((resolve) => server.listen(port, '127.0.0.1', resolve));
  return { clientId, redirectUri, close: () => server.close() };
}

export interface ConformanceAccount {
  did: string;
  handle: string;
  email: string;
  /** The credential the consent form needs; interop sets it during the DID ceremony. */
  password: string;
}

export interface Fixture {
  baseUrl: string;
  account: ConformanceAccount;
  /**
   * The directory the spawned PDS was pointed at, carrying the account's real DID document.
   * A client that resolves DIDs (the official SDK does) must be pointed here too.
   */
  plcUrl: string;
  stop: () => void;
}

/**
 * Spawn a PDS and provision one account.
 *
 * One fixture per test *file*: interop's config module reads `EZPDS_BASE_URL` at first
 * import and caches it, so a second fixture in the same Node process would provision against
 * the first PDS. `node --test` gives each file its own process, which makes this safe as
 * long as the rule is honored.
 */
export async function startFixture(
  options: {
    /**
     * Override `oauth.access_token_ttl_secs`. Set this to a second or two to test what a
     * client sees once its token lapses, without the suite waiting out a real 15-minute
     * token. Tests that use it belong in their own file (see the one-fixture-per-file rule).
     */
    accessTokenTtlSecs?: number;
  } = {},
): Promise<Fixture> {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'custos-oauth-conformance-'));
  const plc = await startMockPlc();
  let pds: SpawnedPds | undefined;
  try {
    // `spawnPds` runs the binary with a closed env allowlist and its cwd set to `dir`, so a
    // setting without an entry in that allowlist is reached by dropping a config file here —
    // the same escape hatch tools/mcp-sidecar uses for its agent_auth scopes.
    if (options.accessTokenTtlSecs !== undefined) {
      fs.writeFileSync(
        path.join(dir, 'pds.toml'),
        `[oauth]\naccess_token_ttl_secs = ${options.accessTokenTtlSecs}\n`,
      );
    }
    pds = await spawnPds({ dir, plcUrl: plc.url, agentAuthEnabled: false });

    process.env.EZPDS_BASE_URL = pds.baseUrl;
    process.env.EZPDS_ADMIN_TOKEN = ADMIN_TOKEN;
    process.env.EZPDS_INTEROP_STATE_DIR = path.join(dir, 'interop-state');
    process.env.EZPDS_INTEROP_PACE_MS = '25';

    const account = await import('ezpds-interop/src/account.js');
    const created = await account.createAccount({
      name: 'oauth-conformance',
      kind: 'ephemeral',
    });
    if (!created.password) {
      throw new Error(
        'interop account ceremony returned no password; the OAuth consent form cannot be ' +
          'driven without one (see tools/interop/src/account.js)',
      );
    }

    // Publish the account's DID document so a client can resolve it. The PDS built this
    // document during the genesis ceremony and serves it back verbatim, so the directory
    // hands out the real thing rather than a test-shaped approximation.
    const described = await fetch(
      `${pds.baseUrl}/xrpc/com.atproto.repo.describeRepo?repo=${encodeURIComponent(created.did)}`,
    );
    if (!described.ok) {
      throw new Error(`could not read the account's DID document: HTTP ${described.status}`);
    }
    const { didDoc } = (await described.json()) as { didDoc?: unknown };
    if (!didDoc) {
      throw new Error('describeRepo returned no didDoc; the mock directory would serve nothing');
    }
    plc.register(created.did, didDoc);

    const spawned = pds;
    return {
      baseUrl: spawned.baseUrl,
      plcUrl: plc.url,
      account: {
        did: created.did,
        handle: created.handle,
        email: created.email,
        password: created.password,
      },
      // Best-effort teardown: attempt every step even if an earlier one throws, because a
      // leaked pds child keeps `node --test` alive on an open handle.
      stop: () => {
        try {
          spawned.stop();
        } catch {
          /* already gone */
        }
        try {
          plc.close();
        } catch {
          /* already gone */
        }
        fs.rmSync(dir, { recursive: true, force: true });
      },
    };
  } catch (err) {
    try {
      pds?.stop();
    } catch {
      /* never started */
    }
    plc.close();
    throw err;
  }
}
