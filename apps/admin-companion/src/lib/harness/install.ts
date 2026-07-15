/**
 * Installs the admin-companion browser test harness.
 *
 * Intercepts Tauri's `invoke`/`listen`/`emit` seam with the official `mockIPC`, so the
 * real Brass Console frontend — every `$lib/ipc` wrapper and its error mapping — runs in
 * a plain browser. Fake mode serves every command from the in-memory relay fake; proxy
 * mode overrides the signed-request subset against a local PDS and falls through to the
 * fake for the rest.
 *
 * Reached only through the dev-gated dynamic import in `src/hooks.client.ts`, so a
 * production build tree-shakes it out (browser-harness.AC4). The marker below is what the
 * build-absence check greps for.
 */
import { mockIPC } from '@tauri-apps/api/mocks';
import { buildRegistry, type Handler, type CommandName } from './registry';
import { buildScenario, DEFAULT_SCENARIO } from './scenarios';
import { createControl, initialScenario } from './control';
import type { AdminState } from './state';

/** Unique sentinel proving this module made it into a bundle (build-absence check). */
export const HARNESS_BUILD_MARKER = '__EZPDS_ADMIN_HARNESS_PRESENT__';

const scenarioFromEnv = (import.meta.env.VITE_HARNESS_SCENARIO as string | undefined) ?? DEFAULT_SCENARIO;

export async function installHarness(modeRaw: string): Promise<void> {
  const mode: 'fake' | 'proxy' = modeRaw === 'proxy' ? 'proxy' : 'fake';
  // Proxy mode starts unpaired by default so the operator pairs with the real PDS
  // (a fake single-relay's device id wouldn't be one the PDS knows). A sticky
  // sessionStorage choice or VITE_HARNESS_SCENARIO still wins.
  const scenarioName = initialScenario(mode === 'proxy' ? 'unpaired' : scenarioFromEnv);

  const state: AdminState = buildScenario(scenarioName);
  const failNext = new Map<string, unknown>();
  const registry = buildRegistry(state);

  let proxyHandlers: Partial<Record<string, Handler>> = {};
  if (mode === 'proxy') {
    const { buildProxyHandlers } = await import('./proxy');
    proxyHandlers = await buildProxyHandlers(state);
  }

  mockIPC(
    (cmd, args) => {
      const a = (args ?? {}) as Record<string, unknown>;

      if (failNext.has(cmd)) {
        const err = failNext.get(cmd);
        failNext.delete(cmd);
        return Promise.reject(err);
      }

      const handler = proxyHandlers[cmd] ?? registry[cmd as CommandName];
      if (!handler) {
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

  const replaceState = (next: AdminState) => {
    const target = state as unknown as Record<string, unknown>;
    for (const key of Object.keys(target)) delete target[key];
    Object.assign(state, next);
  };

  const control = createControl({ state, failNext, replaceState, mode });
  (window as unknown as { __harness: unknown }).__harness = control;

  console.info(
    `%c[harness]%c admin-companion active — mode=${mode}, scenario=${scenarioName}. Drive it via window.__harness (${HARNESS_BUILD_MARKER})`,
    'color:#b8860b;font-weight:bold',
    'color:inherit'
  );
}
