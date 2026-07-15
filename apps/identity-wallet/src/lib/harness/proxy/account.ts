/**
 * Proxy-mode account/claim/identity handlers (browser-harness Phase 5).
 *
 * Placeholder until Phase 5 lands the real-PDS handlers. Returning an empty map means
 * every command falls through to the fake, so proxy mode is a strict superset of fake
 * mode: nothing regresses before the real handlers are wired.
 */
import type { Handler } from '../registry';
import type { WalletState } from '../state';

export async function buildAccountProxyHandlers(
  state: WalletState
): Promise<Partial<Record<string, Handler>>> {
  void state;
  return {};
}
