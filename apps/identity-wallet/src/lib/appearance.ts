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
 *
 * Ordering guarantees:
 * - A user choice made while the launch reconciliation is still in flight is
 *   never clobbered by the (older) stored value (`revision` guard).
 * - Overlapping Keychain writes are serialized (`persistChain`), so the last
 *   selection is also the last write.
 * - A failed Keychain write rolls the mirror back to the last value known to
 *   be persisted, so the next launch paints the durable state instead of an
 *   unsaved choice; the on-screen appearance keeps the user's selection for
 *   the current session (the Settings error copy describes exactly this).
 */
import { getAppearancePreference, setAppearancePreference } from '$lib/ipc';
import type { AppearancePreference } from '$lib/ipc';

export type { AppearancePreference };

/** localStorage key for the pre-paint mirror. Must match the inline script in app.html. */
export const APPEARANCE_STORAGE_KEY = 'appearance-preference';

/** Bumped on every user choice; lets in-flight async work detect it went stale. */
let revision = 0;
/** The newest value confirmed written to the Keychain (null until known). */
let lastPersisted: AppearancePreference | null = null;
/** Keychain writes run strictly in selection order. */
let persistChain: Promise<void> = Promise.resolve();

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
  const seenRevision = revision;
  try {
    const stored = normalizePreference(await getAppearancePreference());
    if (lastPersisted === null) {
      lastPersisted = stored;
    }
    if (revision !== seenRevision) {
      // The user picked an appearance while this read was in flight; the
      // stored value is older than their choice — leave it alone.
      return readLocalMirror();
    }
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
 * The appearance and the mirror commit before the Keychain write runs. On a
 * failed write the returned promise rejects with the AppearanceError and the
 * mirror rolls back to the last persisted value — the current session keeps
 * the user's choice, but the next launch paints the durable state.
 */
export function setAppearance(preference: AppearancePreference): Promise<void> {
  revision += 1;
  const myRevision = revision;
  applyToDocument(preference);
  writeLocalMirror(preference);

  persistChain = persistChain
    // An earlier write's failure already surfaced to its own caller.
    .catch(() => {})
    .then(async () => {
      if (revision !== myRevision) {
        // Superseded before this write started; the newest call persists.
        return;
      }
      try {
        await setAppearancePreference(preference);
        lastPersisted = preference;
      } catch (e) {
        if (revision === myRevision && lastPersisted !== null) {
          writeLocalMirror(lastPersisted);
        }
        throw e;
      }
    });
  return persistChain;
}
