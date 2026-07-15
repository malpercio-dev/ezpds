/**
 * The `window.__harness` runtime control surface for the admin-companion harness.
 *
 * Mirrors the identity-wallet harness API shape exactly (switch scenario, inject a
 * one-shot typed failure, deliver a Tauri event, read a state snapshot) so an agent
 * drives both apps the same way. The admin app subscribes to no Tauri events today, but
 * `emit` is kept for parity and future use — it routes through the real
 * `@tauri-apps/api/event` under `mockIPC(..., { shouldMockEvents: true })`.
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
