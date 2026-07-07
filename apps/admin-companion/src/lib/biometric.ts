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
 * gate resolves to `'unavailable'` rather than throwing. Whenever the plugin IS present we
 * ALWAYS run `authenticate()` — it presents Face ID / Touch ID, or, via
 * `allowDeviceCredential`, the device passcode, and rejects (→ `'denied'`) on cancel/failure
 * or when neither credential exists, so a configured iPhone is always genuinely gated.
 *
 * We deliberately do NOT pre-check `checkStatus().isAvailable` and skip when it is false: on
 * iOS that flag is false when biometrics aren't *enrolled* even though the device still has a
 * passcode that `authenticate()` would gate on, so skipping there would silently drop the
 * user-presence requirement on a real, passcode-protected device. `authenticate()` alone is
 * the authoritative gate. (A simulator with neither an enrolled biometric nor a passcode set
 * will reject here and block — enroll one to test the flow.)
 */
import { biometricEnabled } from './ipc';

/**
 * - `authenticated` — the operator confirmed with Face ID / Touch ID / passcode.
 * - `skipped` — the gate is turned off in Settings.
 * - `unavailable` — the plugin module is not loadable at all (off-device: desktop dev or the
 *   host build). The action is allowed: there is genuinely nothing to gate against here.
 * - `denied` — the operator cancelled, authentication failed, or no credential is enrolled.
 *   The action must NOT run.
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
  // Honor the operator's Settings toggle: an explicit opt-out is not a denial. If the
  // preference can't be read (a keychain hiccup), fail *closed* — default to gated so a
  // failed settings read never drops the user-presence requirement or breaks the action.
  let enabled = true;
  try {
    enabled = await biometricEnabled();
  } catch {
    enabled = true;
  }
  if (!enabled) return 'skipped';

  let plugin: typeof import('@tauri-apps/plugin-biometric');
  try {
    plugin = await import('@tauri-apps/plugin-biometric');
  } catch {
    // Plugin module not loadable (desktop dev / host build) — nothing to gate against.
    return 'unavailable';
  }

  try {
    // Always run authenticate(): it presents biometric-or-passcode and is the authoritative
    // gate. We do NOT short-circuit on checkStatus().isAvailable — that flag is false on a
    // real iPhone that has a passcode but no *enrolled* biometric, and skipping there would
    // drop the user-presence requirement on a device authenticate() could still gate.
    await plugin.authenticate(reason, {
      allowDeviceCredential: true,
      fallbackTitle: 'Use passcode',
      cancelTitle: 'Cancel',
    });
    return 'authenticated';
  } catch {
    // The plugin rejects on user cancel, failed match, or no credential enrolled — block.
    return 'denied';
  }
}
