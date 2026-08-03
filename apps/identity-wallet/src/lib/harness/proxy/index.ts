/**
 * Proxy-mode handlers for the wallet harness (browser-harness Phase 5).
 *
 * Proxy mode is real only for the thin-HTTP subset: `create_account` (mints + redeems a
 * real claim code, POSTs `/v1/accounts/mobile`) and `get_available_user_domains`
 * (describeServer), run against a hermetic local PDS (`just harness-pds`) through the
 * vite dev-server proxy at `/__pds/*` with a real WebCrypto P-256 device key. Every
 * command NOT overridden here falls through to the in-memory fake — by the honest
 * boundary these stay faked even in proxy mode (heavy Rust logic with no thin-HTTP
 * form): the DID ceremonies (`perform_did_ceremony`, `*_did_web_ceremony`), OAuth
 * completion (`prepare/complete_oauth_flow`), the migration transfer legs
 * (`transfer_repo`/`transfer_blobs`/…, `finalize_migration`), recovery/claim PLC ops,
 * and the agent surfaces (which need a real post-ceremony session the faked ceremony
 * never mints).
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
