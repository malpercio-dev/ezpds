import { invoke } from '@tauri-apps/api/core';

// ── Appearance preference ─────────────────────────────────────────────────

/** The in-app appearance setting. 'system' means follow the iOS appearance. */
export type AppearancePreference = 'system' | 'light' | 'dark';

/**
 * Error thrown by `setAppearancePreference`.
 * Serialized as `{ code: "INVALID_PREFERENCE" }` etc. by the Rust backend.
 */
export type AppearanceError =
  | { code: 'INVALID_PREFERENCE' }
  | { code: 'KEYCHAIN_ERROR' };

/**
 * Returns the saved appearance preference, or null if never set (follow the
 * system). The Keychain is the source of truth; `$lib/appearance` mirrors it
 * to localStorage so the choice can apply before first paint.
 */
export const getAppearancePreference = (): Promise<AppearancePreference | null> =>
  invoke('get_appearance_preference');

/**
 * Validates and persists the appearance preference to the Keychain.
 * Throws AppearanceError on failure.
 */
export const setAppearancePreference = (preference: AppearancePreference): Promise<void> =>
  invoke('set_appearance_preference', { preference });
