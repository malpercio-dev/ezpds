/**
 * Client hooks — the browser test harness activation seam.
 *
 * The `init` hook runs once, before the app is rendered, and SvelteKit awaits it — so
 * the Tauri `invoke` mock is installed before `+page.svelte`'s `onMount` fires its first
 * `invoke`. Activation is double-gated:
 *   - `import.meta.env.DEV` — a static guard Vite replaces with `false` in a production
 *     build, so the `import('$lib/harness/install')` below becomes dead code and the
 *     entire harness is tree-shaken out (browser-harness.AC4.2). A build-output grep
 *     (`scripts/check-harness-absence.mjs`) enforces the absence (AC4.1).
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
