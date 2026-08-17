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
//
// It also keeps the ceremony's **rotation key** and publishes the account's PLC audit log,
// which together are what make the wallet consent path drivable: an approval is signed by a
// key in the account's authoritative `rotationKeys`, and the server reads that set live from
// the directory rather than from any cached document.

import * as fs from 'node:fs';
import * as http from 'node:http';
import * as net from 'node:net';
import * as os from 'node:os';
import * as path from 'node:path';

import { ADMIN_TOKEN, spawnPds, type SpawnedPds } from '../../mcp/test/harness.ts';
import { startMockPlc, type MockPlc } from './mock-plc.ts';
import { buildAccountAuditLog } from './plc-audit-log.ts';
import { keypairFromHex, type Keypair } from 'ezpds-interop/src/crypto.js';

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
  // `close()` alone waits for idle keep-alive sockets, which a client that reused a
  // connection leaves open — enough to hold `node --test` past the last assertion.
  return {
    clientId,
    redirectUri,
    close: () => {
      server.closeAllConnections();
      server.close();
    },
  };
}

export interface ConformanceAccount {
  did: string;
  handle: string;
  email: string;
  /** The credential the consent form needs; interop sets it during the DID ceremony. */
  password: string;
  /**
   * `rotationKeys[0]` — the account's root of control, held by the wallet in production and
   * by the test in-process here. Its `did:key` is what an approval envelope names as `key`,
   * and the server accepts the envelope only because this key is in the account's
   * authoritative rotation set (published by the fixture as the account's PLC audit log).
   */
  rotationKey: Keypair;
  rotationKeyId: string;
}

export interface Fixture {
  baseUrl: string;
  account: ConformanceAccount;
  /**
   * The server's own DID, read from `describeServer` rather than derived from the base URL.
   * It is the `aud` of every consent envelope, so a wallet that derived it independently
   * would sign envelopes this server rejects the moment `server_did` is configured.
   */
  serverDid: string;
  /**
   * The directory the spawned PDS was pointed at, carrying the account's real DID document
   * and PLC audit log. A client that resolves DIDs (the official SDK does) must be pointed
   * here too.
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

    // Publish the account's operation log too. `rotationKeys` live only in PLC operations —
    // never in a DID document — and the wallet consent path resolves an approver's authority
    // from the newest non-nullified entry here, live, on every approval.
    plc.registerAuditLog(
      created.did,
      await buildAccountAuditLog(
        {
          did: created.did,
          handle: created.handle,
          rotationKeyId: created.rotationKeyId,
          rotationKeyPrivateHex: created.rotationKeyPrivateHex,
          recoveryKeyId: created.recoveryKeyId,
          repoSigningKeyId: created.repoSigningKeyId,
        },
        pds.baseUrl,
      ),
    );

    // The consent envelope's `aud`. Asked for rather than derived: `resolve_server_did()`
    // prefers a configured `server_did` over the did:web form, and a wallet guessing wrong
    // signs bytes the server will not reconstruct.
    const describedServer = await fetch(
      `${pds.baseUrl}/xrpc/com.atproto.server.describeServer`,
    );
    if (!describedServer.ok) {
      throw new Error(`could not read describeServer: HTTP ${describedServer.status}`);
    }
    const { did: serverDid } = (await describedServer.json()) as { did?: string };
    if (!serverDid) {
      throw new Error('describeServer returned no did; consent envelopes have no audience');
    }

    const spawned = pds;
    return {
      baseUrl: spawned.baseUrl,
      plcUrl: plc.url,
      serverDid,
      account: {
        did: created.did,
        handle: created.handle,
        email: created.email,
        password: created.password,
        rotationKeyId: created.rotationKeyId,
        rotationKey: await keypairFromHex(created.rotationKeyPrivateHex),
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
