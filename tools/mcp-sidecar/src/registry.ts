// The per-caller session registry: the sidecar's replacement for the stdio
// server's singleton `AgentSession`. Keyed by authenticated caller identity (the
// forwarded token's subject), it returns the same `ForwardingSession` object for
// one caller across calls — so per-caller state stays isolated — and distinct
// objects for distinct callers. An unauthenticated request resolves to none.
//
// The registry holds sessions only in memory (never `state.ts`'s `0600` path),
// bounds the map with idle eviction so a long-running process can't accumulate
// callers, and is discarded whole on process exit (nothing survives a restart —
// ADR-0024).

import type { AuthInfo } from '@modelcontextprotocol/sdk/server/auth/types.js';
import { ForwardingSession, callerSubject } from './session.ts';

/** Injected clock so tests drive idle eviction deterministically. */
export type Clock = () => number;

export interface SessionRegistryOptions {
  /** PDS origin every forwarding session forwards to. */
  pdsOrigin: string;
  /** Evict a caller's session after this long without use (default 5 min). */
  idleTtlMs?: number;
  /** Hard cap on concurrent caller sessions (default 10k). */
  maxSessions?: number;
  clock?: Clock;
}

interface Entry {
  session: ForwardingSession;
  lastAccess: number;
}

export class SessionRegistry {
  private readonly pdsOrigin: string;
  private readonly idleTtlMs: number;
  private readonly maxSessions: number;
  private readonly clock: Clock;
  private readonly entries = new Map<string, Entry>();

  constructor(options: SessionRegistryOptions) {
    this.pdsOrigin = options.pdsOrigin;
    this.idleTtlMs = options.idleTtlMs ?? 5 * 60_000;
    this.maxSessions = options.maxSessions ?? 10_000;
    this.clock = options.clock ?? (() => Date.now());
  }

  /**
   * Resolve the forwarding session for a request's authenticated caller, with
   * the request's token bound. Returns `null` when the request carries no usable
   * credential — the caller is unauthenticated and no session is minted. For an
   * authenticated caller, the same object is returned across calls (so per-caller
   * state is isolated), rebound to the request's current token so the freshest
   * credential is forwarded without being cached.
   */
  resolve(authInfo: AuthInfo | undefined): ForwardingSession | null {
    const token = authInfo?.token;
    if (!token) return null;

    this.evictIdle();

    const key = callerSubject(token);
    const now = this.clock();
    const existing = this.entries.get(key);
    if (existing) {
      existing.session.bindToken(token, authInfo.scopes);
      existing.lastAccess = now;
      return existing.session;
    }

    this.enforceCap();
    const session = new ForwardingSession(this.pdsOrigin);
    session.bindToken(token, authInfo.scopes);
    this.entries.set(key, { session, lastAccess: now });
    return session;
  }

  /**
   * Release the token bound to a caller's session once the request resolves.
   * The session object stays in the map (caller identity / reuse), but it holds
   * no credential between requests — ADR-0024's "nothing durable" extends to
   * in-memory linger, not just disk.
   */
  release(authInfo: AuthInfo | undefined): void {
    const token = authInfo?.token;
    if (!token) return;
    this.entries.get(callerSubject(token))?.session.releaseToken();
  }

  /** The caller's session without rebinding a token (for tests/inspection). */
  peek(subject: string): ForwardingSession | undefined {
    return this.entries.get(subject)?.session;
  }

  /** Number of live caller sessions (for tests/metrics). */
  size(): number {
    return this.entries.size;
  }

  /** Forget every session — the whole in-memory state, e.g. on shutdown. */
  clear(): void {
    this.entries.clear();
  }

  private evictIdle(): void {
    const cutoff = this.clock() - this.idleTtlMs;
    for (const [key, entry] of this.entries) {
      if (entry.lastAccess < cutoff) this.entries.delete(key);
    }
  }

  /** When at capacity, drop the least-recently-used session to make room. */
  private enforceCap(): void {
    if (this.entries.size < this.maxSessions) return;
    let oldestKey: string | null = null;
    let oldest = Infinity;
    for (const [key, entry] of this.entries) {
      if (entry.lastAccess < oldest) {
        oldest = entry.lastAccess;
        oldestKey = key;
      }
    }
    if (oldestKey !== null) this.entries.delete(oldestKey);
  }
}
