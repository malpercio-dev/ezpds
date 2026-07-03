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
    const checkStatus = vi.fn().mockResolvedValue({ isAvailable: true });
    const authenticate = vi.fn().mockResolvedValue(undefined);
    vi.doMock('@tauri-apps/plugin-biometric', () => ({ checkStatus, authenticate }));

    const { requireUserPresence } = await loadBiometric();
    await expect(requireUserPresence('Generate a claim code')).resolves.toBe('authenticated');
    expect(checkStatus).toHaveBeenCalledOnce();
    expect(authenticate).toHaveBeenCalledWith('Generate a claim code', {
      allowDeviceCredential: true,
      fallbackTitle: 'Use passcode',
      cancelTitle: 'Cancel',
    });
  });

  it('fails closed (stays gated, does not skip) when the preference read errors', async () => {
    vi.doMock('./ipc', () => ({
      biometricEnabled: vi.fn().mockRejectedValue(new Error('keychain unavailable')),
    }));
    const checkStatus = vi.fn().mockResolvedValue({ isAvailable: true });
    // Authenticate is cancelled — if the gate had failed *open* (treating the read
    // error as "disabled"), this rejection would never be reached and the outcome
    // would be 'skipped' instead of 'denied'.
    const authenticate = vi.fn().mockRejectedValue(new Error('user cancelled'));
    vi.doMock('@tauri-apps/plugin-biometric', () => ({ checkStatus, authenticate }));

    const { requireUserPresence } = await loadBiometric();
    await expect(requireUserPresence('Revoke this device')).resolves.toBe('denied');
    expect(checkStatus).toHaveBeenCalledOnce();
    expect(authenticate).toHaveBeenCalledOnce();
  });

  it('fails closed to the gate, which resolves to unavailable, when the preference read errors and there is no hardware', async () => {
    vi.doMock('./ipc', () => ({
      biometricEnabled: vi.fn().mockRejectedValue(new Error('keychain unavailable')),
    }));
    const checkStatus = vi.fn().mockResolvedValue({ isAvailable: false });
    const authenticate = vi.fn();
    vi.doMock('@tauri-apps/plugin-biometric', () => ({ checkStatus, authenticate }));

    const { requireUserPresence } = await loadBiometric();
    await expect(requireUserPresence('Generate a claim code')).resolves.toBe('unavailable');
    expect(checkStatus).toHaveBeenCalledOnce();
    expect(authenticate).not.toHaveBeenCalled();
  });

  it('resolves to unavailable when the plugin module fails to import (desktop/host build)', async () => {
    vi.doMock('./ipc', () => ({ biometricEnabled: vi.fn().mockResolvedValue(true) }));
    vi.doMock('@tauri-apps/plugin-biometric', () => {
      throw new Error('module not found');
    });

    const { requireUserPresence } = await loadBiometric();
    await expect(requireUserPresence('Generate a claim code')).resolves.toBe('unavailable');
  });

  it('resolves to unavailable when checkStatus reports no available hardware', async () => {
    vi.doMock('./ipc', () => ({ biometricEnabled: vi.fn().mockResolvedValue(true) }));
    const checkStatus = vi.fn().mockResolvedValue({ isAvailable: false });
    const authenticate = vi.fn();
    vi.doMock('@tauri-apps/plugin-biometric', () => ({ checkStatus, authenticate }));

    const { requireUserPresence } = await loadBiometric();
    await expect(requireUserPresence('Generate a claim code')).resolves.toBe('unavailable');
    expect(authenticate).not.toHaveBeenCalled();
  });

  it('resolves to denied when the operator cancels or authentication fails', async () => {
    vi.doMock('./ipc', () => ({ biometricEnabled: vi.fn().mockResolvedValue(true) }));
    const checkStatus = vi.fn().mockResolvedValue({ isAvailable: true });
    const authenticate = vi.fn().mockRejectedValue(new Error('authentication failed'));
    vi.doMock('@tauri-apps/plugin-biometric', () => ({ checkStatus, authenticate }));

    const { requireUserPresence } = await loadBiometric();
    await expect(requireUserPresence('Generate a claim code')).resolves.toBe('denied');
  });

  it('resolves to denied when checkStatus itself throws', async () => {
    vi.doMock('./ipc', () => ({ biometricEnabled: vi.fn().mockResolvedValue(true) }));
    const checkStatus = vi.fn().mockRejectedValue(new Error('hardware query failed'));
    const authenticate = vi.fn();
    vi.doMock('@tauri-apps/plugin-biometric', () => ({ checkStatus, authenticate }));

    const { requireUserPresence } = await loadBiometric();
    await expect(requireUserPresence('Generate a claim code')).resolves.toBe('denied');
    expect(authenticate).not.toHaveBeenCalled();
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
