// A completed login, for tests whose subject is what happens *after* one.
//
// flow.test.ts deliberately does not use this: its job is to assert each leg of the flow
// separately. Everything else just needs a working session, and open-coding the four legs in
// every file makes the interesting assertions hard to find.

import assert from 'node:assert/strict';

import { approveConsent } from '../src/consent.ts';
import {
  generateDpopKey,
  par,
  pkce,
  tokenRequestWithNonceRetry,
  type DpopKey,
  type ServerMetadata,
} from '../src/wire-client.ts';
import type { ClientHost, Fixture } from './fixture.ts';

export interface Session {
  accessToken: string;
  refreshToken: string;
  /** The DPoP key the tokens are bound to. */
  key: DpopKey;
  /** What the token endpoint reported, for tests asserting on the response itself. */
  tokenResponse: any;
}

/** Drive PAR → consent → token exchange and return the resulting session. */
export async function login(
  fixture: Fixture,
  client: ClientHost,
  metadata: ServerMetadata,
  opts: { scope?: string } = {},
): Promise<Session> {
  const key = await generateDpopKey();
  const { verifier, challenge } = pkce();

  const pushed = await par(metadata, {
    client_id: client.clientId,
    redirect_uri: client.redirectUri,
    response_type: 'code',
    code_challenge: challenge,
    code_challenge_method: 'S256',
    scope: opts.scope ?? 'atproto transition:generic',
  });
  assert.equal(pushed.status, 201, `PAR must succeed: ${pushed.text}`);

  const approval = await approveConsent(
    fixture.baseUrl,
    `${metadata.authorization_endpoint}?client_id=${encodeURIComponent(client.clientId)}` +
      `&request_uri=${encodeURIComponent(pushed.json.request_uri)}`,
    { identifier: fixture.account.did, password: fixture.account.password },
  );
  const code = approval.params.get('code');
  assert.ok(code, `consent must yield a code: ${approval.location}`);

  const exchange = await tokenRequestWithNonceRetry(metadata, key, {
    grant_type: 'authorization_code',
    code,
    redirect_uri: client.redirectUri,
    client_id: client.clientId,
    code_verifier: verifier,
  });
  assert.equal(exchange.final.status, 200, `token exchange must succeed: ${exchange.final.text}`);

  return {
    accessToken: exchange.final.json.access_token,
    refreshToken: exchange.final.json.refresh_token,
    key,
    tokenResponse: exchange.final.json,
  };
}
