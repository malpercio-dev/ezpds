// The auth.md onboarding flow and agent session lifecycle:
//
//   discover   GET /.well-known/oauth-protected-resource → AS metadata → auth.md
//   register   POST {identity_endpoint}  type=service_auth, login_hint=<email>
//   claim      surface user_code + verification_uri to the human, then poll
//              POST {token_endpoint}  grant_type=urn:workos:agent-auth:grant-type:claim
//   exchange   POST {token_endpoint}  grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer
//
// Agent access tokens are short-lived (~5 min) with no refresh token; the
// service-signed identity assertion is the durable credential and is
// re-exchanged transparently until it expires. Revocation in the wallet makes
// the exchange fail with access_denied — we then stop and require explicit
// user action (never auto-re-register).

import { request, HttpError, sleep } from './http.ts';
import { loginEmail } from './config.ts';
import {
  loadCredentials,
  saveCredentials,
  clearCredentials,
  type CachedCredentials,
} from './state.ts';

const CLAIM_GRANT = 'urn:workos:agent-auth:grant-type:claim';
const JWT_BEARER_GRANT = 'urn:ietf:params:oauth:grant-type:jwt-bearer';

/** Thrown when the server says this registration was revoked. */
export class RevokedError extends Error {
  constructor() {
    super(
      'This agent was revoked in Obsign. It will not re-register itself: to onboard again, ' +
        'the account owner must run `custos-mcp reset` (or delete the cached-credentials file) ' +
        'and restart the server, then confirm the new claim ceremony.',
    );
  }
}

/** Thrown when the identity assertion has expired and a new ceremony is needed. */
export class SessionExpiredError extends Error {
  constructor() {
    super(
      'The agent session has expired (the identity assertion outlived its TTL). ' +
        'A new claim ceremony has to be confirmed by the account owner — restart the ' +
        'MCP server to begin one, or call the whoami tool after restart for the claim code.',
    );
  }
}

export interface Discovery {
  authorizationServer: string;
  tokenEndpoint: string;
  identityEndpoint: string;
  claimEndpoint: string;
  /** URL of the auth.md skill document. */
  skill: string | null;
  identityTypesSupported: string[];
}

/** Decode a JWT payload without verifying — we only read our own credentials. */
export function decodeJwtPayload(jwt: string): Record<string, unknown> {
  const part = jwt.split('.')[1];
  if (!part) throw new Error('malformed JWT');
  return JSON.parse(Buffer.from(part, 'base64url').toString('utf8'));
}

/**
 * The discovery walk from the auth.md spec: PRM names the authorization
 * server, its metadata carries the agent_auth block, which points at the
 * auth.md skill document and the agent endpoints.
 */
export async function discover(pdsUrl: string): Promise<Discovery> {
  const prm = await request(`${pdsUrl}/.well-known/oauth-protected-resource`);
  const authorizationServer: string = (prm.authorization_servers?.[0] ?? pdsUrl).replace(
    /\/+$/,
    '',
  );

  const as = await request(`${authorizationServer}/.well-known/oauth-authorization-server`);
  const agentAuth = as.agent_auth;
  if (!agentAuth || !agentAuth.identity_endpoint) {
    throw new Error(
      `${pdsUrl} does not advertise agent authentication (no agent_auth block in its ` +
        'authorization-server metadata). This PDS cannot onboard agents via auth.md.',
    );
  }

  return {
    authorizationServer,
    tokenEndpoint: as.token_endpoint,
    identityEndpoint: agentAuth.identity_endpoint,
    claimEndpoint: agentAuth.claim_endpoint,
    skill: agentAuth.skill ?? null,
    identityTypesSupported: agentAuth.identity_types_supported ?? [],
  };
}

export interface RegistrationResult {
  registrationId: string;
  claimToken: string;
  userCode: string;
  verificationUri: string;
  expiresAt: string;
}

/**
 * Register via the service_auth flow (email as login_hint). The server starts
 * a claim ceremony bound to the matching local account and hands back the
 * user_code the human must confirm.
 */
export async function registerServiceAuth(
  discovery: Discovery,
  email: string,
): Promise<RegistrationResult> {
  let response;
  try {
    response = await request(discovery.identityEndpoint, {
      method: 'POST',
      body: { type: 'service_auth', login_hint: email },
    });
  } catch (err) {
    if (err instanceof HttpError && err.errorCode?.endsWith('_not_enabled')) {
      throw new Error(
        `This PDS has the ${err.errorCode.replace('_not_enabled', '')} agent registration ` +
          `flow disabled (${err.errorCode}). Ask the operator to enable ` +
          `[agent_auth] service_auth_enabled, or check auth.md at ` +
          `${discovery.skill ?? 'the service root'} for supported flows.`,
      );
    }
    if (err instanceof HttpError && err.errorCode === 'access_denied') {
      throw new Error(
        `The PDS rejected registration: ${err.errorDescription ?? 'access denied'}. ` +
          `Check that CUSTOS_MCP_EMAIL (${email}) matches an account on this PDS.`,
      );
    }
    throw err;
  }

  return {
    registrationId: response.registration_id,
    claimToken: response.claim_token,
    userCode: response.claim.user_code,
    verificationUri: response.claim.verification_uri,
    expiresAt: response.claim.expires_at,
  };
}

export interface ClaimGrantResult {
  accessToken: string;
  expiresIn: number;
  scope: string;
  assertion: string;
  assertionExpires: string;
}

/**
 * Poll the token endpoint with the claim grant until the human confirms.
 * Device-flow etiquette: wait `interval` between polls, add 5s on slow_down,
 * cap the backoff.
 */
export async function pollClaim(
  discovery: Discovery,
  claimToken: string,
  options: { intervalSecs?: number; onPending?: () => void } = {},
): Promise<ClaimGrantResult> {
  let interval = (options.intervalSecs ?? 5) * 1000;
  const maxInterval = 60_000;

  for (;;) {
    await sleep(interval);
    try {
      const token = await request(discovery.tokenEndpoint, {
        method: 'POST',
        body: new URLSearchParams({ grant_type: CLAIM_GRANT, claim_token: claimToken }),
      });
      return {
        accessToken: token.access_token,
        expiresIn: token.expires_in,
        scope: token.scope ?? '',
        assertion: token.identity_assertion,
        assertionExpires: token.assertion_expires,
      };
    } catch (err) {
      if (!(err instanceof HttpError)) throw err;
      switch (err.errorCode) {
        case 'authorization_pending':
          options.onPending?.();
          continue;
        case 'slow_down':
          interval = Math.min(interval + 5_000, maxInterval);
          continue;
        case 'expired_token':
          throw new Error(
            'The claim ceremony expired before it was confirmed. Restart the MCP server ' +
              'to begin a new one.',
          );
        case 'access_denied':
          throw new RevokedError();
        default:
          throw err;
      }
    }
  }
}

/**
 * Exchange the identity assertion for a fresh access token (RFC 7523
 * JWT-bearer grant). The token inherits the assertion's scopes verbatim.
 */
export async function exchangeAssertion(
  tokenEndpoint: string,
  assertion: string,
  resource: string,
): Promise<{ accessToken: string; expiresIn: number; scope: string }> {
  try {
    const token = await request(tokenEndpoint, {
      method: 'POST',
      body: new URLSearchParams({
        grant_type: JWT_BEARER_GRANT,
        assertion,
        resource: `${resource}/`,
      }),
    });
    return {
      accessToken: token.access_token,
      expiresIn: token.expires_in,
      scope: token.scope ?? '',
    };
  } catch (err) {
    if (err instanceof HttpError) {
      if (err.errorCode === 'access_denied') throw new RevokedError();
      if (err.errorCode === 'invalid_grant') throw new SessionExpiredError();
    }
    throw err;
  }
}

export type SessionState =
  | { state: 'onboarding'; userCode: string; verificationUri: string; expiresAt: string }
  | { state: 'ready'; did: string; scopes: string[]; registrationId: string | null }
  | { state: 'revoked' }
  | { state: 'expired' }
  | { state: 'error'; message: string };

/**
 * One agent session against one PDS. Owns the cached credentials, runs the
 * onboarding ceremony when there are none, and hands out a live access token
 * to the tool layer (re-exchanging the assertion transparently).
 */
export class AgentSession {
  readonly pdsUrl: string;
  private discovery: Discovery | null = null;
  private creds: CachedCredentials | null;
  private onboarding: RegistrationResult | null = null;
  private onboardingError: string | null = null;

  constructor(pdsUrl: string) {
    this.pdsUrl = pdsUrl;
    this.creds = loadCredentials(pdsUrl);
  }

  private async discovered(): Promise<Discovery> {
    this.discovery ??= await discover(this.pdsUrl);
    return this.discovery;
  }

  /** True if the assertion in the cache is present and unexpired. */
  private assertionValid(): boolean {
    if (!this.creds?.assertion) return false;
    try {
      const exp = decodeJwtPayload(this.creds.assertion).exp;
      return typeof exp === 'number' && exp * 1000 > Date.now() + 10_000;
    } catch {
      return false;
    }
  }

  status(): SessionState {
    if (this.creds?.revoked) return { state: 'revoked' };
    if (this.onboarding) {
      return {
        state: 'onboarding',
        userCode: this.onboarding.userCode,
        verificationUri: this.onboarding.verificationUri,
        expiresAt: this.onboarding.expiresAt,
      };
    }
    if (this.onboardingError) return { state: 'error', message: this.onboardingError };
    if (this.assertionValid()) {
      return {
        state: 'ready',
        did: this.creds!.did ?? '(unknown)',
        scopes: this.creds!.scopes ?? [],
        registrationId: this.creds!.registrationId ?? null,
      };
    }
    if (this.creds?.assertion) return { state: 'expired' };
    return { state: 'error', message: 'not onboarded yet' };
  }

  /** Whether startup needs to run a claim ceremony. */
  needsOnboarding(): boolean {
    return !this.creds?.revoked && !this.assertionValid();
  }

  /**
   * Run registration (fails fast and legibly when the PDS has agent auth
   * disabled), then poll for the human confirmation in the background.
   * Returns after registration; `onReady`/`onFailed` fire from the poll loop.
   */
  async startOnboarding(callbacks: {
    onWaiting: (reg: RegistrationResult) => void;
    onReady: (state: SessionState) => void;
    onFailed: (err: Error) => void;
  }): Promise<void> {
    const email = loginEmail();
    if (!email) {
      throw new Error(
        'CUSTOS_MCP_EMAIL is not set. First-run onboarding registers this agent against ' +
          'your account by email — set it in the MCP server config (see tools/mcp/README.md).',
      );
    }

    const discovery = await this.discovered();
    // Complete the spec's discovery walk: the skill document is the prose
    // half of the contract. We don't parse it, but a server that fails to
    // serve it is worth flagging before we register.
    if (discovery.skill) {
      try {
        await request(discovery.skill);
      } catch (err) {
        process.stderr.write(
          `[custos-mcp] warning: ${discovery.skill} is advertised but not readable ` +
            `(${err instanceof Error ? err.message : err})\n`,
        );
      }
    }
    const registration = await registerServiceAuth(discovery, email);
    this.onboarding = registration;
    this.onboardingError = null;
    callbacks.onWaiting(registration);

    void pollClaim(discovery, registration.claimToken)
      .then((granted) => {
        const payload = decodeJwtPayload(granted.assertion);
        this.creds = {
          pdsUrl: this.pdsUrl,
          registrationId: registration.registrationId,
          assertion: granted.assertion,
          accessToken: granted.accessToken,
          accessTokenExpiresAt: Math.floor(Date.now() / 1000) + granted.expiresIn,
          scopes: granted.scope ? granted.scope.split(' ') : [],
          did: typeof payload.sub === 'string' ? payload.sub : undefined,
        };
        saveCredentials(this.creds);
        this.onboarding = null;
        callbacks.onReady(this.status());
      })
      .catch((err: Error) => {
        this.onboarding = null;
        if (err instanceof RevokedError && this.creds) {
          this.creds.revoked = true;
          saveCredentials(this.creds);
        }
        this.onboardingError = err.message;
        callbacks.onFailed(err);
      });
  }

  /**
   * A live access token for tool calls. Re-exchanges the assertion when the
   * cached token is missing or within 30s of expiry.
   */
  async accessToken(): Promise<string> {
    if (this.creds?.revoked) throw new RevokedError();
    if (this.onboarding) {
      throw new Error(
        `Onboarding is not finished: ask the account owner to confirm claim code ` +
          `${this.onboarding.userCode} at ${this.onboarding.verificationUri} (or in the ` +
          `Obsign wallet), then try again.`,
      );
    }
    if (!this.creds?.assertion) {
      throw new Error(
        this.onboardingError
          ? `Onboarding failed: ${this.onboardingError}`
          : 'No credentials for this PDS yet — restart the MCP server to onboard.',
      );
    }
    if (!this.assertionValid()) throw new SessionExpiredError();

    const now = Math.floor(Date.now() / 1000);
    if (this.creds.accessToken && (this.creds.accessTokenExpiresAt ?? 0) > now + 30) {
      return this.creds.accessToken;
    }

    const discovery = await this.discovered();
    try {
      const token = await exchangeAssertion(
        discovery.tokenEndpoint,
        this.creds.assertion,
        this.pdsUrl,
      );
      this.creds.accessToken = token.accessToken;
      this.creds.accessTokenExpiresAt = now + token.expiresIn;
      this.creds.scopes = token.scope ? token.scope.split(' ') : this.creds.scopes;
      saveCredentials(this.creds);
      return token.accessToken;
    } catch (err) {
      if (err instanceof RevokedError) {
        this.creds.revoked = true;
        this.creds.accessToken = undefined;
        this.creds.accessTokenExpiresAt = undefined;
        saveCredentials(this.creds);
      }
      throw err;
    }
  }

  /** The DID this session acts as, once onboarded. */
  did(): string | null {
    return this.creds?.did ?? null;
  }

  scopes(): string[] {
    return this.creds?.scopes ?? [];
  }

  /** Explicit user action: forget everything about this PDS. */
  reset(): void {
    clearCredentials(this.pdsUrl);
    this.creds = null;
    this.onboarding = null;
    this.onboardingError = null;
  }
}
