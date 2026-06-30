/**
 * The biometric (user-presence) gate on signing actions.
 *
 * Every action that signs with the device key (generating a claim code, revoking this
 * device) calls {@link requireUserPresence} first, so a momentary unlock can't mint admin
 * credentials without the operator present. The check is in the frontend rather than the
 * Rust signing command because the plugin is mobile-only and the WKWebView is the *only*
 * IPC client — there is no untrusted code path that could call `invoke()` around the gate.
 *
 * The plugin (`@tauri-apps/plugin-biometric`) exists only on iOS/Android, so it is
 * imported dynamically: off-device (desktop dev, the host build) the import fails and the
 * gate resolves to `'unavailable'` rather than throwing. On a real device with Face ID /
 * Touch ID enrolled it prompts; `allowDeviceCredential` lets a device without enrolled
 * biometrics fall back to the passcode, so a configured iPhone is always genuinely gated.
 */
import { biometricEnabled } from './ipc';

/**
 * - `authenticated` — the operator confirmed with Face ID / Touch ID / passcode.
 * - `skipped` — the gate is turned off in Settings.
 * - `unavailable` — no plugin or hardware (off-device, or a simulator with no enrolled
 *   biometric). The action is allowed: there is nothing to gate against here.
 * - `denied` — the operator cancelled or authentication failed. The action must NOT run.
 */
export type PresenceOutcome = 'authenticated' | 'skipped' | 'unavailable' | 'denied';

/** Whether an outcome permits the guarded action to proceed. Only `denied` blocks. */
export function presenceAllows(outcome: PresenceOutcome): boolean {
  return outcome !== 'denied';
}

/**
 * Gate a signing action behind user presence. `reason` is shown in the system prompt
 * (e.g. "Generate a claim code"). Returns how the gate resolved; callers proceed unless
 * the outcome is `denied`.
 */
export async function requireUserPresence(reason: string): Promise<PresenceOutcome> {
  // Honor the operator's Settings toggle: an explicit opt-out is not a denial.
  if (!(await biometricEnabled())) return 'skipped';

  let plugin: typeof import('@tauri-apps/plugin-biometric');
  try {
    plugin = await import('@tauri-apps/plugin-biometric');
  } catch {
    // Plugin not present (desktop dev / host build) — nothing to gate against.
    return 'unavailable';
  }

  try {
    const status = await plugin.checkStatus();
    if (!status.isAvailable) return 'unavailable';
    await plugin.authenticate(reason, {
      allowDeviceCredential: true,
      fallbackTitle: 'Use passcode',
      cancelTitle: 'Cancel',
    });
    return 'authenticated';
  } catch {
    // The plugin rejects on user cancel or failed match — block the action.
    return 'denied';
  }
}
