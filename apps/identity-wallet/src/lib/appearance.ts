/**
 * In-app appearance override (System / Light / Dark).
 *
 * The mechanism is one line: every color token is a `light-dark()` pair keyed
 * off `color-scheme` (set to `light dark` on :root in base.css), so forcing an
 * appearance is just an inline `color-scheme` override on <html>, and clearing
 * it returns the app to system-follow.
 *
 * Persistence is two-layer:
 * - The **Keychain** (via the `get/set_appearance_preference` IPC pair) is the
 *   durable source of truth, matching the app's persistence story.
 * - A **localStorage mirror** exists only so the preference can apply before
 *   first paint: app.html reads it synchronously in an inline <head> script,
 *   because an async IPC read would land after the WebView has painted and
 *   flash the wrong appearance. `initAppearance()` reconciles the mirror
 *   against the Keychain at launch — the Keychain always wins.
 */
import { getAppearancePreference, setAppearancePreference } from '$lib/ipc';
import type { AppearancePreference } from '$lib/ipc';

export type { AppearancePreference };

/** localStorage key for the pre-paint mirror. Must match the inline script in app.html. */
export const APPEARANCE_STORAGE_KEY = 'appearance-preference';

/** Coerce any stored/received value to a valid preference ('system' when unrecognized). */
export function normalizePreference(value: unknown): AppearancePreference {
  return value === 'light' || value === 'dark' ? value : 'system';
}

/** The `color-scheme` override a preference maps to ('' = follow the system). */
export function toColorScheme(preference: AppearancePreference): '' | 'light' | 'dark' {
  return preference === 'system' ? '' : preference;
}

function applyToDocument(preference: AppearancePreference): void {
  document.documentElement.style.colorScheme = toColorScheme(preference);
}

/** Read the localStorage mirror (never throws; storage errors mean 'system'). */
export function readLocalMirror(): AppearancePreference {
  try {
    return normalizePreference(localStorage.getItem(APPEARANCE_STORAGE_KEY));
  } catch {
    return 'system';
  }
}

function writeLocalMirror(preference: AppearancePreference): void {
  try {
    if (preference === 'system') {
      localStorage.removeItem(APPEARANCE_STORAGE_KEY);
    } else {
      localStorage.setItem(APPEARANCE_STORAGE_KEY, preference);
    }
  } catch (e) {
    console.warn('Could not write appearance mirror to localStorage:', e);
  }
}

/**
 * Launch-time restore: re-assert the mirror (a no-op after app.html's inline
 * script), then reconcile against the Keychain. Returns the effective
 * preference so callers can seed UI state.
 */
export async function initAppearance(): Promise<AppearancePreference> {
  const mirrored = readLocalMirror();
  applyToDocument(mirrored);
  try {
    const stored = normalizePreference(await getAppearancePreference());
    if (stored !== mirrored) {
      applyToDocument(stored);
      writeLocalMirror(stored);
    }
    return stored;
  } catch (e) {
    // Keychain unreadable: keep whatever the mirror said. Worst case is
    // system-follow, which is the default behavior anyway.
    console.warn('Could not restore appearance preference from Keychain:', e);
    return mirrored;
  }
}

/**
 * Apply a preference instantly and persist it (mirror + Keychain).
 *
 * The appearance and the mirror are already committed by the time the
 * Keychain write runs, so a thrown AppearanceError means only that the
 * durable copy failed — callers should surface that without reverting.
 */
export async function setAppearance(preference: AppearancePreference): Promise<void> {
  applyToDocument(preference);
  writeLocalMirror(preference);
  await setAppearancePreference(preference);
}
