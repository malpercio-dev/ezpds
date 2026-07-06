import { describe, it, expect, vi, beforeEach } from 'vitest';

// The biometric plugin is mobile-only; mock it so we can drive checkStatus/authenticate
// outcomes and assert the gate's fail-open vs fail-closed behavior.
const checkStatus = vi.fn();
const authenticate = vi.fn();
vi.mock('@tauri-apps/plugin-biometric', () => ({
  get checkStatus() {
    return checkStatus;
  },
  get authenticate() {
    return authenticate;
  },
}));

import { authenticateBiometric } from './ipc';

describe('authenticateBiometric', () => {
  beforeEach(() => {
    checkStatus.mockReset();
    authenticate.mockReset();
  });

  it('prompts and resolves when biometric hardware is available', async () => {
    checkStatus.mockResolvedValue({ isAvailable: true });
    authenticate.mockResolvedValue(undefined);

    await expect(authenticateBiometric('reason')).resolves.toBeUndefined();
    expect(authenticate).toHaveBeenCalledWith('reason', { allowDeviceCredential: true });
  });

  it('proceeds without prompting when no biometric hardware is enrolled (bare simulator)', async () => {
    checkStatus.mockResolvedValue({ isAvailable: false });

    await expect(authenticateBiometric('reason')).resolves.toBeUndefined();
    expect(authenticate).not.toHaveBeenCalled();
  });

  it('fails closed when checkStatus rejects on a real device (transient plugin/OS error)', async () => {
    // A registered-but-erroring plugin (keystore hiccup, permission race) must NOT be
    // treated as "no gate": swallowing it would silently skip the approval boundary.
    checkStatus.mockRejectedValue(new Error('keystore unavailable'));

    await expect(authenticateBiometric('reason')).rejects.toThrow();
    expect(authenticate).not.toHaveBeenCalled();
  });

  it('fails closed when the operator cancels or authentication fails', async () => {
    checkStatus.mockResolvedValue({ isAvailable: true });
    authenticate.mockRejectedValue(new Error('user cancelled'));

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
      expect(checkStatus).not.toHaveBeenCalled();
      expect(authenticate).not.toHaveBeenCalled();
    } finally {
      vi.doUnmock('@tauri-apps/plugin-biometric');
      vi.resetModules();
    }
  });
});
