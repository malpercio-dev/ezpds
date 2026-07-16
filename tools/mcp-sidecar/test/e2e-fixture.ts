// End-to-end fixture: the composition Phase 3 exists to prove. It stands up the
// full hosted path against a hermetic PDS —
//
//   spawnPds (tools/mcp harness)      the real pds binary, mock plc.directory,
//                                     TLS-fronted (needs CUSTOS_MCP_TEST_TLS_DIR,
//                                     set by run-e2e.ts)
//   provisionAccount                  a real parent account, full wallet ceremony
//   mintChild                         POST /agent/child with a wallet-signed
//                                     genesis op — the sovereign child (MM-368)
//   exchangeChildToken                RFC 7523 jwt-bearer: the child's identity
//                                     assertion → a short-lived Bearer, exactly
//                                     what a real caller forwards
//   startSidecar + connect            the forwarding sidecar (MM-369) and an MCP
//                                     HTTP client bound to that Bearer
//
// The wallet-held rotation key is generated HERE, caller-side, and never leaves
// the fixture: the PDS only ever sees the signed genesis op, mirroring the real
// custody split (ADR-0023). Every AC3 test drives this one spine.

import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import type { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { newKeypair, buildGenesisOp, randomSuffix } from 'ezpds-interop/src/crypto.js';
import {
  spawnPds,
  startMockPlc,
  provisionAccount,
  type SpawnedPds,
  type TestAccount,
} from '../../mcp/test/harness.ts';
import { startSidecar, connectClient, type RunningSidecar } from './support.ts';

/** The sovereign child minted for the test run. */
export interface MintedChild {
  did: string;
  handle: string;
  registrationId: string;
  /** The service-signed identity assertion — the caller's durable credential. */
  identityAssertion: string;
  scopes: string[];
}

/** A legible token-endpoint failure (`{error, error_description}`). */
export class TokenExchangeError extends Error {
  readonly code: string;
  readonly description: string;

  constructor(code: string, description: string) {
    super(`token exchange failed (${code}): ${description}`);
    this.code = code;
    this.description = description;
  }
}

export interface E2eFixture {
  pds: SpawnedPds;
  parent: TestAccount;
  child: MintedChild;
  sidecar: RunningSidecar;
  /**
   * Exchange the child's identity assertion for a fresh access token — what a
   * real caller's session does before forwarding. Throws `TokenExchangeError`
   * (e.g. `access_denied` after revocation).
   */
  exchangeChildToken(): Promise<string>;
  /** Connect an MCP client to the sidecar, forwarding `token` if given. */
  connect(token?: string): Promise<Client>;
  close(): Promise<void>;
}

/** GET an XRPC query on the hermetic PDS directly, bypassing the sidecar. */
export async function xrpcGet(
  baseUrl: string,
  method: string,
  params: Record<string, string>,
): Promise<any> {
  const url = new URL(`${baseUrl}/xrpc/${method}`);
  for (const [key, value] of Object.entries(params)) url.searchParams.set(key, value);
  const res = await fetch(url);
  const body = await res.json();
  if (!res.ok) {
    throw new Error(`${method} failed (${res.status}): ${JSON.stringify(body)}`);
  }
  return body;
}

async function postJson(
  url: string,
  body: unknown,
  token?: string,
): Promise<{ status: number; body: any }> {
  const res = await fetch(url, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      ...(token ? { authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify(body),
  });
  return { status: res.status, body: await res.json() };
}

/**
 * Mint a sovereign child of `parent` through the real Phase-1 surface: reserve a
 * repo signing key on the PDS, build and sign the did:plc genesis op with a
 * fixture-held ("wallet") rotation key, and POST /agent/child as the parent.
 */
async function mintChild(baseUrl: string, parent: TestAccount): Promise<MintedChild> {
  const reserved = await postJson(`${baseUrl}/xrpc/com.atproto.server.reserveSigningKey`, {});
  if (reserved.status !== 200) {
    throw new Error(`reserveSigningKey failed (${reserved.status}): ${JSON.stringify(reserved.body)}`);
  }
  const repoSigningKeyId: string = reserved.body.signingKey;

  // The recovery/rotation key: held by the fixture (standing in for the Obsign
  // wallet), signs the genesis op, never sent to the server.
  const walletKey = await newKeypair();
  const handle = `agent-${randomSuffix(6)}.localhost`;
  const { did, signedOp } = await buildGenesisOp({
    rotationKeyId: walletKey.keyId,
    repoSigningKeyId,
    rotationKeypair: walletKey.keypair,
    handle,
    pdsUrl: baseUrl,
  });

  const minted = await postJson(
    `${baseUrl}/agent/child`,
    { handle, plcOp: signedOp },
    parent.accessJwt,
  );
  if (minted.status !== 200) {
    throw new Error(`POST /agent/child failed (${minted.status}): ${JSON.stringify(minted.body)}`);
  }
  if (minted.body.did !== did) {
    throw new Error(`child DID mismatch: locally derived ${did}, server minted ${minted.body.did}`);
  }
  return {
    did,
    handle,
    registrationId: minted.body.registrationId,
    identityAssertion: minted.body.identityAssertion,
    scopes: minted.body.scopes,
  };
}

/** RFC 7523 jwt-bearer exchange: identity assertion → short-lived Bearer token. */
async function exchangeAssertion(baseUrl: string, assertion: string): Promise<string> {
  const res = await fetch(`${baseUrl}/oauth/token`, {
    method: 'POST',
    body: new URLSearchParams({
      grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
      assertion,
      resource: `${baseUrl}/`,
    }),
  });
  const body = (await res.json()) as {
    error?: string;
    error_description?: string;
    access_token?: string;
  };
  if (!res.ok || !body.access_token) {
    throw new TokenExchangeError(
      body.error ?? 'unknown_error',
      body.error_description ?? 'no details provided',
    );
  }
  return body.access_token;
}

/**
 * Stand the whole path up. `grantedScopes` narrows the PDS's
 * `[agent_auth] granted_scopes` via a pds.toml in the spawn dir (there is no env
 * override for it); the minted child's capability is clamped to exactly that set
 * — the lever the scope-refusal test uses.
 *
 * One fixture per test FILE: the interop account ceremony reads its base-URL
 * config at first import, so a second `provisionAccount` in the same process
 * would silently target the first PDS. `node --test` runs each file in its own
 * child process, which keeps that constraint invisible as long as a file spawns
 * only one fixture.
 */
export async function startE2eFixture(
  options: { grantedScopes?: string[] } = {},
): Promise<E2eFixture> {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'custos-sidecar-e2e-'));
  if (options.grantedScopes) {
    const scopes = options.grantedScopes.map((scope) => JSON.stringify(scope)).join(', ');
    fs.writeFileSync(path.join(dir, 'pds.toml'), `[agent_auth]\ngranted_scopes = [${scopes}]\n`);
  }

  const plc = await startMockPlc();
  let pds: SpawnedPds | undefined;
  let sidecar: RunningSidecar | undefined;
  try {
    pds = await spawnPds({ dir, plcUrl: plc.url, agentAuthEnabled: true });
    const parent = await provisionAccount(pds.baseUrl, path.join(dir, 'interop-state'));
    const child = await mintChild(pds.baseUrl, parent);
    sidecar = await startSidecar({ MCP_SIDECAR_PDS_ORIGIN: pds.baseUrl });

    const running = { pds, sidecar };
    return {
      pds,
      parent,
      child,
      sidecar,
      exchangeChildToken: () => exchangeAssertion(running.pds.baseUrl, child.identityAssertion),
      connect: (token?: string) => connectClient(running.sidecar.url, token),
      close: async () => {
        await running.sidecar.close();
        running.pds.stop();
        plc.close();
        fs.rmSync(dir, { recursive: true, force: true });
      },
    };
  } catch (err) {
    await sidecar?.close();
    pds?.stop();
    plc.close();
    fs.rmSync(dir, { recursive: true, force: true });
    throw err;
  }
}
