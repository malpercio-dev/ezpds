import { describe, it, expect, vi, beforeEach } from 'vitest';

// `biometric.ts` resolves `./ipc` (a static import) and `@tauri-apps/plugin-biometric`
// (a dynamic import inside `requireUserPresence`) differently per test, so both are
// mocked per-test with `vi.doMock` + `vi.resetModules()` + a fresh dynamic `import('./biometric')`
// rather than a single hoisted `vi.mock`.

async function loadBiometric() {
  return await import('./biometric');
}

beforeEach(() => {
  vi.resetModules();
});

describe('requireUserPresence', () => {
  it('skips the gate when the biometric preference is disabled', async () => {
    vi.doMock('./ipc', () => ({ biometricEnabled: vi.fn().mockResolvedValue(false) }));
    const checkStatus = vi.fn();
    const authenticate = vi.fn();
    vi.doMock('@tauri-apps/plugin-biometric', () => ({ checkStatus, authenticate }));

    const { requireUserPresence } = await loadBiometric();
    await expect(requireUserPresence('Generate a claim code')).resolves.toBe('skipped');
    expect(checkStatus).not.toHaveBeenCalled();
    expect(authenticate).not.toHaveBeenCalled();
  });

  it('authenticates when the preference is enabled and the plugin succeeds', async () => {
    vi.doMock('./ipc', () => ({ biometricEnabled: vi.fn().mockResolvedValue(true) }));
    const authenticate = vi.fn().mockResolvedValue(undefined);
    vi.doMock('@tauri-apps/plugin-biometric', () => ({ authenticate }));

    const { requireUserPresence } = await loadBiometric();
    await expect(requireUserPresence('Generate a claim code')).resolves.toBe('authenticated');
    expect(authenticate).toHaveBeenCalledWith('Generate a claim code', {
      allowDeviceCredential: true,
      fallbackTitle: 'Use passcode',
      cancelTitle: 'Cancel',
    });
  });

  it('always reaches authenticate() when the plugin is present — never pre-skips on availability', async () => {
    // Regression: a real iPhone with a passcode but no enrolled biometric reports
    // checkStatus().isAvailable === false, yet authenticate() with allowDeviceCredential can
    // still gate via the passcode. The gate must run authenticate() rather than short-circuit
    // to 'unavailable' and let the signing action proceed ungated. If checkStatus is even
    // consulted its rejection here would surface, so we assert it is never called.
    vi.doMock('./ipc', () => ({ biometricEnabled: vi.fn().mockResolvedValue(true) }));
    const checkStatus = vi.fn().mockResolvedValue({ isAvailable: false });
    const authenticate = vi.fn().mockResolvedValue(undefined);
    vi.doMock('@tauri-apps/plugin-biometric', () => ({ checkStatus, authenticate }));

    const { requireUserPresence } = await loadBiometric();
    await expect(requireUserPresence('Generate a claim code')).resolves.toBe('authenticated');
    expect(checkStatus).not.toHaveBeenCalled();
    expect(authenticate).toHaveBeenCalledOnce();
  });

  it('resolves to denied (blocks) when no credential is enrolled — authenticate rejects', async () => {
    // Regression: on a device with neither an enrolled biometric nor a passcode,
    // authenticate() rejects. That must block the signing action, NOT resolve to 'unavailable'
    // and let it through.
    vi.doMock('./ipc', () => ({ biometricEnabled: vi.fn().mockResolvedValue(true) }));
    const authenticate = vi.fn().mockRejectedValue(new Error('biometryNotAvailable'));
    vi.doMock('@tauri-apps/plugin-biometric', () => ({ authenticate }));

    const { requireUserPresence } = await loadBiometric();
    await expect(requireUserPresence('Generate a claim code')).resolves.toBe('denied');
    expect(authenticate).toHaveBeenCalledOnce();
  });

  it('fails closed (stays gated, does not skip) when the preference read errors', async () => {
    vi.doMock('./ipc', () => ({
      biometricEnabled: vi.fn().mockRejectedValue(new Error('keychain unavailable')),
    }));
    // Authenticate is cancelled — if the gate had failed *open* (treating the read
    // error as "disabled"), this rejection would never be reached and the outcome
    // would be 'skipped' instead of 'denied'.
    const authenticate = vi.fn().mockRejectedValue(new Error('user cancelled'));
    vi.doMock('@tauri-apps/plugin-biometric', () => ({ authenticate }));

    const { requireUserPresence } = await loadBiometric();
    await expect(requireUserPresence('Revoke this device')).resolves.toBe('denied');
    expect(authenticate).toHaveBeenCalledOnce();
  });

  it('resolves to unavailable only when the plugin module fails to import (desktop/host build)', async () => {
    vi.doMock('./ipc', () => ({ biometricEnabled: vi.fn().mockResolvedValue(true) }));
    vi.doMock('@tauri-apps/plugin-biometric', () => {
      throw new Error('module not found');
    });

    const { requireUserPresence } = await loadBiometric();
    await expect(requireUserPresence('Generate a claim code')).resolves.toBe('unavailable');
  });

  it('resolves to denied when the operator cancels or authentication fails', async () => {
    vi.doMock('./ipc', () => ({ biometricEnabled: vi.fn().mockResolvedValue(true) }));
    const authenticate = vi.fn().mockRejectedValue(new Error('authentication failed'));
    vi.doMock('@tauri-apps/plugin-biometric', () => ({ authenticate }));

    const { requireUserPresence } = await loadBiometric();
    await expect(requireUserPresence('Generate a claim code')).resolves.toBe('denied');
  });
});

describe('presenceAllows', () => {
  it('allows authenticated, skipped, and unavailable outcomes', async () => {
    const { presenceAllows } = await loadBiometric();
    expect(presenceAllows('authenticated')).toBe(true);
    expect(presenceAllows('skipped')).toBe(true);
    expect(presenceAllows('unavailable')).toBe(true);
  });

  it('blocks only the denied outcome', async () => {
    const { presenceAllows } = await loadBiometric();
    expect(presenceAllows('denied')).toBe(false);
  });
});
