/**
 * Client hooks — the browser test harness activation seam.
 *
 * The `init` hook runs once, before the app renders, and SvelteKit awaits it — so the
 * Tauri `invoke` mock is installed before any screen's first `invoke`. Double-gated:
 *   - `import.meta.env.DEV` — a static guard Vite replaces with `false` in production, so
 *     the harness import becomes dead code and is tree-shaken out
 *     (browser-harness.AC4.2; enforced by scripts/check-harness-absence.mjs).
 *   - `import.meta.env.VITE_HARNESS` — the opt-in flag (`fake` | `proxy`). Plain
 *     `pnpm dev` leaves it unset, so the harness never activates implicitly (AC1.5).
 */
import type { ClientInit } from '@sveltejs/kit';

export const init: ClientInit = async () => {
  if (import.meta.env.DEV && import.meta.env.VITE_HARNESS) {
    const { installHarness } = await import('$lib/harness/install');
    await installHarness(import.meta.env.VITE_HARNESS as string);
  }
};
