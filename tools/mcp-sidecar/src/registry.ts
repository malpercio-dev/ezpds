// The per-caller registry: the sidecar's replacement for the stdio server's
// singleton `AgentSession`. It tracks distinct authenticated callers (keyed by
// the forwarded token's subject) so a long-running process can bound and evict
// them — but it stores NO credential. Each `resolve` mints a fresh,
// request-scoped `ForwardingSession` bound to that request's token, so two
// concurrent requests (even from the same caller) get independent sessions and
// neither can observe, overwrite, or release the other's token. An
// unauthenticated request resolves to none. Nothing survives a restart (ADR-0024).

import type { AuthInfo } from '@modelcontextprotocol/sdk/server/auth/types.js';
import { ForwardingSession, callerSubject } from './session.ts';

/** Injected clock so tests drive idle eviction deterministically. */
export type Clock = () => number;

export interface SessionRegistryOptions {
  /** PDS origin every forwarding session forwards to. */
  pdsOrigin: string;
  /** Evict a caller's tracking entry after this long without use (default 5 min). */
  idleTtlMs?: number;
  /** Hard cap on distinct tracked callers (default 10k). */
  maxCallers?: number;
  clock?: Clock;
}

/** Per-caller bookkeeping. Deliberately holds NO credential — only liveness. */
interface CallerEntry {
  lastAccess: number;
}

export class SessionRegistry {
  private readonly pdsOrigin: string;
  private readonly idleTtlMs: number;
  private readonly maxCallers: number;
  private readonly clock: Clock;
  private readonly callers = new Map<string, CallerEntry>();

  constructor(options: SessionRegistryOptions) {
    this.pdsOrigin = options.pdsOrigin;
    this.idleTtlMs = options.idleTtlMs ?? 5 * 60_000;
    this.maxCallers = options.maxCallers ?? 10_000;
    this.clock = options.clock ?? (() => Date.now());
  }

  /**
   * Mint the request-scoped forwarding session for a request's authenticated
   * caller. Returns `null` when the request carries no usable credential — the
   * caller is unauthenticated and no session is minted. For an authenticated
   * caller the returned session is FRESH per call and bound to this request's
   * token; the registry only records that the caller is live (for eviction and
   * metrics), never the credential itself.
   */
  resolve(authInfo: AuthInfo | undefined): ForwardingSession | null {
    const token = authInfo?.token;
    if (!token) return null;

    this.evictIdle();

    const key = callerSubject(token);
    if (!this.callers.has(key)) this.enforceCap();
    this.callers.set(key, { lastAccess: this.clock() });

    return new ForwardingSession(this.pdsOrigin, token, authInfo.scopes);
  }

  /** Number of live distinct callers (for tests/metrics). */
  size(): number {
    return this.callers.size;
  }

  /** Forget every tracked caller — the whole in-memory state, e.g. on shutdown. */
  clear(): void {
    this.callers.clear();
  }

  private evictIdle(): void {
    const cutoff = this.clock() - this.idleTtlMs;
    for (const [key, entry] of this.callers) {
      if (entry.lastAccess < cutoff) this.callers.delete(key);
    }
  }

  /** When at capacity, drop the least-recently-seen caller to make room. */
  private enforceCap(): void {
    if (this.callers.size < this.maxCallers) return;
    let oldestKey: string | null = null;
    let oldest = Infinity;
    for (const [key, entry] of this.callers) {
      if (entry.lastAccess < oldest) {
        oldest = entry.lastAccess;
        oldestKey = key;
      }
    }
    if (oldestKey !== null) this.callers.delete(oldestKey);
  }
}
