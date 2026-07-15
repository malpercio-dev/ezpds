// A per-caller forwarding session. This is the sidecar's answer to the stdio
// server's `AgentSession`: it satisfies the same `SessionLike` shape the shared
// tool surface consumes, but instead of onboarding, exchanging assertions, and
// caching credentials `0600` on disk, it holds only the caller's already-minted
// OAuth bearer — and only for the life of one request — then attaches it to each
// forwarded XRPC call.
//
// ADR-0024: it persists NOTHING durable. No assertion, no access token on disk,
// no refresh, no file. The token is bound at the start of a request and
// released the moment that request resolves, so between requests the session
// object (kept for caller identity/reuse) carries no credential at all; on
// process restart nothing is recoverable. The tool code paths call
// `accessToken()` transparently, so the shared surface needs no per-tool change.

// Imported by relative path into the sibling stdio package (not the `ezpds-mcp`
// specifier): Node will not type-strip `.ts` resolved under `node_modules`, and
// neither package has a build step. See the note in server.ts.
import type { SessionLike } from '../../mcp/src/tools.ts';
import { decodeJwtPayload, type SessionState } from '../../mcp/src/auth.ts';

/**
 * The caller's stable identity for keying the session registry: the `sub` of
 * the forwarded token (the acting DID). Falls back to a token-identity marker
 * only if the token has no readable subject, so distinct opaque tokens still map
 * to distinct sessions rather than colliding.
 */
export function callerSubject(token: string): string {
  try {
    const sub = decodeJwtPayload(token).sub;
    if (typeof sub === 'string' && sub) return sub;
  } catch {
    // Not a decodable JWT — fall through to the token-identity fallback.
  }
  return `opaque:${token}`;
}

export class ForwardingSession implements SessionLike {
  readonly pdsUrl: string;
  private token: string | null = null;
  private grantedScopes: string[] = [];

  constructor(pdsOrigin: string) {
    this.pdsUrl = pdsOrigin;
  }

  /**
   * Bind the current request's token. The registry returns the same session
   * object for a caller across calls (so identity/isolation hold), but each
   * request binds its own short-lived token here — the forwarded credential
   * stays fresh and is never cached beyond the request.
   */
  bindToken(token: string, scopes?: string[]): void {
    this.token = token;
    this.grantedScopes = scopes?.length ? scopes : scopesFromToken(token);
  }

  /** Drop the bound token once its request resolves — nothing lingers. */
  releaseToken(): void {
    this.token = null;
    this.grantedScopes = [];
  }

  /** Whether a token is currently bound (for tests/assertions). */
  hasBoundToken(): boolean {
    return this.token !== null;
  }

  /** The forwarded caller token — returned as-is, never exchanged or cached. */
  accessToken(): Promise<string> {
    if (this.token === null) {
      return Promise.reject(
        new Error('no forwarded credential bound to this request — the caller must authenticate'),
      );
    }
    return Promise.resolve(this.token);
  }

  /** The acting DID, read from the forwarded token's subject claim. */
  did(): string | null {
    if (this.token === null) return null;
    try {
      const sub = decodeJwtPayload(this.token).sub;
      return typeof sub === 'string' ? sub : null;
    } catch {
      return null;
    }
  }

  scopes(): string[] {
    return this.grantedScopes;
  }

  status(): SessionState {
    return {
      state: 'ready',
      did: this.did() ?? '(unknown)',
      scopes: this.grantedScopes,
      registrationId: null,
    };
  }
}

/** Read space-delimited scopes from a token's `scope` claim, if present. */
function scopesFromToken(token: string): string[] {
  try {
    const scope = decodeJwtPayload(token).scope;
    return typeof scope === 'string' && scope ? scope.split(' ') : [];
  } catch {
    return [];
  }
}
