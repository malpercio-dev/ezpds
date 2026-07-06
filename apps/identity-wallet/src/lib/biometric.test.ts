import { describe, it, expect, vi, beforeEach } from 'vitest';

// The biometric plugin is mobile-only; mock it so we can drive authenticate() outcomes and
// assert the gate's fail-open (import missing) vs fail-closed (plugin present) behavior.
const authenticate = vi.fn();
vi.mock('@tauri-apps/plugin-biometric', () => ({
  get authenticate() {
    return authenticate;
  },
}));

import { authenticateBiometric } from './ipc';

describe('authenticateBiometric', () => {
  beforeEach(() => {
    authenticate.mockReset();
  });

  it('prompts and resolves when the plugin is present and authentication succeeds', async () => {
    authenticate.mockResolvedValue(undefined);

    await expect(authenticateBiometric('reason')).resolves.toBeUndefined();
    expect(authenticate).toHaveBeenCalledWith('reason', { allowDeviceCredential: true });
  });

  it('always invokes authenticate() when the plugin is present — never pre-skips on availability', async () => {
    // Regression: a real iPhone with a passcode but no enrolled biometric reports
    // checkStatus().isAvailable === false, yet authenticate() with allowDeviceCredential can
    // still gate via the passcode. The gate must reach authenticate() rather than short-circuit.
    authenticate.mockResolvedValue(undefined);

    await authenticateBiometric('reason');
    expect(authenticate).toHaveBeenCalledTimes(1);
  });

  it('fails closed when the operator cancels or authentication fails', async () => {
    authenticate.mockRejectedValue(new Error('user cancelled'));

    await expect(authenticateBiometric('reason')).rejects.toThrow();
  });

  it('fails closed when no biometric or passcode credential is available (authenticate rejects)', async () => {
    // On a bare simulator with neither enrolled biometric nor passcode, authenticate() rejects.
    // That must block the irreversible submission, not silently skip the gate.
    authenticate.mockRejectedValue(new Error('biometryNotAvailable'));

    await expect(authenticateBiometric('reason')).rejects.toThrow();
  });

  it('proceeds without gating when the plugin module cannot be imported at all', async () => {
    // The one fail-OPEN branch: if the dynamic import itself throws, the plugin genuinely
    // isn't loadable (there is nothing to gate against), so resolve without touching the
    // plugin. A fresh module registry lets us swap in a throwing import factory.
    vi.resetModules();
    vi.doMock('@tauri-apps/plugin-biometric', () => {
      throw new Error('module not resolvable');
    });
    try {
      const { authenticateBiometric: freshGate } = await import('./ipc');
      await expect(freshGate('reason')).resolves.toBeUndefined();
      expect(authenticate).not.toHaveBeenCalled();
    } finally {
      vi.doUnmock('@tauri-apps/plugin-biometric');
      vi.resetModules();
    }
  });
});
