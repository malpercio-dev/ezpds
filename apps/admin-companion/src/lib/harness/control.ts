/**
 * The `window.__harness` runtime control surface for the admin-companion harness.
 *
 * Mirrors the identity-wallet harness API shape exactly (switch scenario, inject a
 * one-shot typed failure, deliver a Tauri event, read a state snapshot) so an agent
 * drives both apps the same way. `emit` routes through the real `@tauri-apps/api/event`
 * under `mockIPC(..., { shouldMockEvents: true })`; the one listener is the root layout's
 * `notification_route` (a tapped operator alert), which re-reads the pending route via
 * `take_pending_notification_route` — always `null` in the browser.
 */
import { emit } from '@tauri-apps/api/event';
import { buildScenario, scenarios } from './scenarios';
import type { AdminState } from './state';

const SCENARIO_KEY = 'ezpds-harness-scenario';

export interface HarnessControl {
  readonly mode: 'fake' | 'proxy';
  readonly scenarios: string[];
  scenario(name: string, opts?: { reload?: boolean }): void;
  failNext(command: string, error: unknown): void;
  emit(event: string, payload?: unknown): Promise<void>;
  state(): AdminState;
}

export interface ControlContext {
  state: AdminState;
  failNext: Map<string, unknown>;
  replaceState: (next: AdminState) => void;
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
        // sessionStorage unavailable — the in-place path below still works.
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

export function initialScenario(fallback: string): string {
  try {
    const stored = sessionStorage.getItem(SCENARIO_KEY);
    if (stored) return stored;
  } catch {
    // ignore
  }
  return fallback;
}
