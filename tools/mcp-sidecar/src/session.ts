// A per-request forwarding session. This is the sidecar's answer to the stdio
// server's `AgentSession`: it satisfies the same `SessionLike` shape the shared
// tool surface consumes, but instead of onboarding, exchanging assertions, and
// caching credentials `0600` on disk, it carries only the caller's already-minted
// OAuth bearer and attaches it to each forwarded XRPC call.
//
// It is IMMUTABLE and REQUEST-SCOPED: constructed fresh for each request, bound
// to that request's token at construction, and never mutated or shared. Two
// concurrent requests — even from the same caller — hold distinct session objects,
// so one can never overwrite or release the other's credential. The token lives
// only on the request-scoped object, which becomes unreachable once the request
// resolves; nothing durable is written and nothing survives a restart (ADR-0024).

import { createHash } from 'node:crypto';
import type { SessionLike } from '../../mcp/src/tools.ts';
import { decodeJwtPayload, type SessionState } from '../../mcp/src/auth.ts';

/**
 * The caller's stable identity for keying the session registry: the `sub` of
 * the forwarded token (the acting DID). For an opaque (non-JWT) token with no
 * readable subject, key by a one-way SHA-256 digest instead of the token itself,
 * so the raw credential is never retained — not even as a map key (ADR-0024).
 * Distinct tokens still map to distinct keys; the same token maps stably.
 */
export function callerSubject(token: string): string {
  try {
    const sub = decodeJwtPayload(token).sub;
    if (typeof sub === 'string' && sub) return sub;
  } catch {
    // Not a decodable JWT — fall through to the digest-based fallback.
  }
  return `opaque:${createHash('sha256').update(token).digest('hex')}`;
}

export class ForwardingSession implements SessionLike {
  readonly pdsUrl: string;
  private readonly token: string;
  private readonly grantedScopes: string[];

  constructor(pdsOrigin: string, token: string, scopes?: string[]) {
    this.pdsUrl = pdsOrigin;
    this.token = token;
    this.grantedScopes = scopes?.length ? scopes : scopesFromToken(token);
  }

  /** The forwarded caller token — returned as-is, never exchanged or cached. */
  accessToken(): Promise<string> {
    return Promise.resolve(this.token);
  }

  /** The acting DID, read from the forwarded token's subject claim. */
  did(): string | null {
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
