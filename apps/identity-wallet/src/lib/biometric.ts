/**
 * Prompt for biometric authentication (Face ID / Touch ID) via `@tauri-apps/plugin-biometric`.
 * Gates the PLC-op submission in the migration review screen — the user is the signer, so this
 * is the authorization boundary for an irreversible identity change, not decorative confirmation.
 *
 * This is a policy gate, not an `invoke()` wrapper: it lives outside `$lib/ipc/` (matching the
 * sibling admin-companion app's `$lib/biometric.ts`) because it drives the mobile-only biometric
 * plugin directly rather than calling a Rust command. The IPC callers that must gate a signing
 * action (sovereign login, agent claim/revoke, migration/did:web submission) import it from here.
 *
 * Because it is a security boundary it must fail CLOSED. The plugin exists only on iOS/Android,
 * so it is imported dynamically. The ONLY case we skip is the dynamic import itself throwing —
 * the plugin module is genuinely unloadable (a host build with no plugin), so there is nothing
 * to gate against and we resolve. Whenever the plugin IS present we ALWAYS run `authenticate()`:
 * it presents Face ID / Touch ID, or — via `allowDeviceCredential` — the device passcode, and
 * rejects on cancel/failure so the caller aborts the submission.
 *
 * We deliberately do NOT pre-check `checkStatus().isAvailable` and skip when it is false: on iOS
 * that flag is false when biometrics aren't *enrolled* even though the device still has a
 * passcode that `authenticate()` would gate on, so skipping there would drop the approval gate on
 * a real device. `authenticate()` alone is the authoritative gate. (A simulator with neither an
 * enrolled biometric nor a passcode set will reject here and block — enroll one to test the
 * flow.)
 */
export const authenticateBiometric = async (reason: string): Promise<void> => {
  let plugin: typeof import('@tauri-apps/plugin-biometric');
  try {
    plugin = await import('@tauri-apps/plugin-biometric');
  } catch {
    return; // plugin module not loadable (host build) — nothing to gate against.
  }
  await plugin.authenticate(reason, { allowDeviceCredential: true });
};
