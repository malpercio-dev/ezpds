/**
 * The `window.__harness` runtime control surface for the wallet harness.
 *
 * This is what an agent (or a human) drives from the browser console to script the
 * fake: switch scenario presets, inject a one-shot typed command failure, deliver a
 * Tauri event to live `listen()` subscribers, and read a snapshot of the fake store.
 *
 * `emit` routes through Tauri's real `@tauri-apps/api/event` `emit()` — which, under
 * `mockIPC(..., { shouldMockEvents: true })`, is delivered to the app's live listeners.
 * So `window.__harness.emit('auth_ready')` exercises the exact `listen('auth_ready')`
 * path the OAuth deep-link return would (browser-harness.AC2.4).
 */
import { emit } from '@tauri-apps/api/event';
import { buildScenario, scenarios } from './scenarios';
import type { WalletState } from './state';

const SCENARIO_KEY = 'ezpds-harness-scenario';

/** The console-facing control API attached to `window.__harness`. */
export interface HarnessControl {
  /** The active harness mode. */
  readonly mode: 'fake' | 'proxy';
  /** The names of every available scenario preset. */
  readonly scenarios: string[];
  /**
   * Switch to a named scenario preset. By default persists the choice and reloads so
   * every screen re-renders from the new state; pass `{ reload: false }` to reseed the
   * live store in place without a reload (the next navigation/mount re-fetches).
   */
  scenario(name: string, opts?: { reload?: boolean }): void;
  /**
   * Make the NEXT invocation of `command` reject with `error` (a typed IPC error shape,
   * e.g. `{ code: 'EXPIRED_CODE' }`). One-shot: consumed by the next call.
   */
  failNext(command: string, error: unknown): void;
  /** Deliver a Tauri event to live `listen()` subscribers. */
  emit(event: string, payload?: unknown): Promise<void>;
  /** A deep-cloned, read-only snapshot of the current fake store. */
  state(): WalletState;
}

/** Context the control surface manipulates; owned by `install.ts`. */
export interface ControlContext {
  state: WalletState;
  failNext: Map<string, unknown>;
  replaceState: (next: WalletState) => void;
  mode: 'fake' | 'proxy';
}

export function createControl(ctx: ControlContext): HarnessControl {
  return {
    mode: ctx.mode,
    scenarios: Object.keys(scenarios),
    scenario(name, opts) {
      try {
        sessionStorage.setItem(SCENARIO_KEY, name);
      } catch {
        // sessionStorage may be unavailable; the in-place path below still works.
      }
      if (opts?.reload === false) {
        ctx.replaceState(buildScenario(name));
      } else {
        location.reload();
      }
    },
    failNext(command, error) {
      ctx.failNext.set(command, error);
    },
    emit(event, payload) {
      return emit(event, payload);
    },
    state() {
      return structuredClone(ctx.state);
    },
  };
}

/** The scenario to seed on install: a sticky sessionStorage choice, else the env/default. */
export function initialScenario(fallback: string): string {
  try {
    const stored = sessionStorage.getItem(SCENARIO_KEY);
    if (stored) return stored;
  } catch {
    // ignore — fall through to the fallback
  }
  return fallback;
}
