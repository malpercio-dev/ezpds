/**
 * Installs the identity-wallet browser test harness.
 *
 * Intercepts Tauri's `invoke`/`listen`/`emit` seam with the official `mockIPC`
 * (`@tauri-apps/api/mocks`), so the real frontend code path — including every `$lib/ipc`
 * wrapper, its error mapping, and `listen()` — runs unchanged in a plain browser. Two
 * modes share this one install and one registry; only the handler set differs:
 *  - **fake** (default): every command is served by the stateful in-memory fake;
 *  - **proxy**: the thin-HTTP command subset is served for real against a local PDS
 *    (proxy handlers), everything else falls through to the fake.
 *
 * This module is only ever reached through the dev-gated dynamic import in
 * `src/hooks.client.ts`, so a production build tree-shakes it out entirely
 * (browser-harness.AC4). The marker below is what the build-absence check greps for.
 */
import { mockIPC } from '@tauri-apps/api/mocks';
import { buildRegistry, type Handler, type CommandName } from './registry';
import { buildScenario } from './scenarios';
import { createControl, initialScenario } from './control';
import { DEFAULT_SCENARIO } from './scenarios';
import type { WalletState } from './state';

/**
 * Unique sentinel proving this module was included in a bundle. The build-absence
 * check (`scripts/check-harness-absence.mjs`) greps `dist/` for it and fails if present.
 */
export const HARNESS_BUILD_MARKER = '__EZPDS_WALLET_HARNESS_PRESENT__';

/** The environment variable that selects the scenario preset (optional). */
const scenarioFromEnv = (import.meta.env.VITE_HARNESS_SCENARIO as string | undefined) ?? DEFAULT_SCENARIO;

export async function installHarness(modeRaw: string): Promise<void> {
  const mode: 'fake' | 'proxy' = modeRaw === 'proxy' ? 'proxy' : 'fake';
  const scenarioName = initialScenario(scenarioFromEnv);

  // The live fake store. Kept as a stable object reference so registry/proxy closures
  // and `replaceState` (scenario switch without reload) all see the same instance.
  const state: WalletState = buildScenario(scenarioName);
  const failNext = new Map<string, unknown>();
  const registry = buildRegistry(state);

  // In proxy mode, load the real-PDS handlers that override the thin-HTTP subset.
  let proxyHandlers: Partial<Record<string, Handler>> = {};
  if (mode === 'proxy') {
    const { buildProxyHandlers } = await import('./proxy');
    proxyHandlers = await buildProxyHandlers(state);
  }

  mockIPC(
    (cmd, args) => {
      const a = (args ?? {}) as Record<string, unknown>;

      // One-shot injected failure wins over any handler (browser-harness.AC2.3).
      if (failNext.has(cmd)) {
        const err = failNext.get(cmd);
        failNext.delete(cmd);
        return Promise.reject(err);
      }

      const handler = proxyHandlers[cmd] ?? registry[cmd as CommandName];
      if (!handler) {
        // A command with no fake handler is a coverage gap — loud, never silent.
        console.error(`[harness] no handler registered for command: ${cmd}`);
        return Promise.reject({
          code: 'HARNESS_NO_HANDLER',
          message: `No harness handler for command '${cmd}'`,
        });
      }
      return Promise.resolve(handler(a));
    },
    { shouldMockEvents: true }
  );

  const replaceState = (next: WalletState) => {
    // Mutate the existing object in place so every closure keeps its reference valid.
    const target = state as unknown as Record<string, unknown>;
    for (const key of Object.keys(target)) delete target[key];
    Object.assign(state, next);
  };

  const control = createControl({ state, failNext, replaceState, mode });
  (window as unknown as { __harness: unknown }).__harness = control;

  console.info(
    `%c[harness]%c wallet active — mode=${mode}, scenario=${scenarioName}. Drive it via window.__harness (${HARNESS_BUILD_MARKER})`,
    'color:#b8860b;font-weight:bold',
    'color:inherit'
  );
}
