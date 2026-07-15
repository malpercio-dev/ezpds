/**
 * Proxy-mode handlers for the admin-companion harness (browser-harness Phase 6).
 *
 * In proxy mode the signed-request operator surface (pairing bootstrap, claim-code
 * minting, device listing) runs for real against a hermetic local PDS reached through
 * the vite dev-server proxy at `/__pds/*`, using a real WebCrypto P-256 admin device key
 * to sign the canonical request envelopes. Every command NOT overridden here falls
 * through to the in-memory fake.
 */
import type { Handler } from '../registry';
import type { AdminState } from '../state';

export async function buildProxyHandlers(
  state: AdminState
): Promise<Partial<Record<string, Handler>>> {
  const { buildOperatorProxyHandlers } = await import('./operator');
  return {
    ...(await buildOperatorProxyHandlers(state)),
  };
}
