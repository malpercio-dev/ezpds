/**
 * Proxy-mode operator handlers (browser-harness Phase 6).
 *
 * Placeholder until Phase 6 lands the signed-request handlers against a real local PDS.
 * An empty map means every command falls through to the fake, so proxy mode is a strict
 * superset of fake mode and nothing regresses before the real handlers are wired.
 */
import type { Handler } from '../registry';
import type { AdminState } from '../state';

export async function buildOperatorProxyHandlers(
  state: AdminState
): Promise<Partial<Record<string, Handler>>> {
  void state;
  return {};
}
