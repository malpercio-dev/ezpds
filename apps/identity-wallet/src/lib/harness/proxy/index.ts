/**
 * Proxy-mode handlers for the wallet harness (browser-harness Phase 5).
 *
 * In proxy mode the thin-HTTP command subset (account creation, handle/domain queries,
 * identity resolution, agent list/revoke/audit) runs for real against a hermetic local
 * PDS reached through the vite dev-server proxy at `/__pds/*`, using a real WebCrypto
 * P-256 device key for signatures. Every command NOT overridden here falls through to
 * the in-memory fake — including the deliberately fake-only heavy-logic commands
 * (migration transfer legs, DID ceremony internals, OAuth completion; see the runbook).
 */
import type { Handler } from '../registry';
import type { WalletState } from '../state';

/**
 * Build the proxy handler overrides. Returns an empty map to fall entirely through to
 * the fake until Phase 5 wires the real-PDS handlers; kept as an async factory so the
 * WebCrypto key setup and any PDS discovery can be awaited there.
 */
export async function buildProxyHandlers(
  state: WalletState
): Promise<Partial<Record<string, Handler>>> {
  const { buildAccountProxyHandlers } = await import('./account');
  return {
    ...(await buildAccountProxyHandlers(state)),
  };
}
