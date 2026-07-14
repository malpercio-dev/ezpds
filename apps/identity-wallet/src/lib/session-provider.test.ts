import { beforeEach, describe, expect, it, vi } from 'vitest';

const invoke = vi.fn();
const authenticate = vi.fn();

vi.mock('@tauri-apps/api/core', () => ({
  get invoke() {
    return invoke;
  },
}));
vi.mock('@tauri-apps/plugin-biometric', () => ({
  get authenticate() {
    return authenticate;
  },
}));

import { ensureIdentitySession } from './ipc';

describe('ensureIdentitySession', () => {
  beforeEach(() => {
    invoke.mockReset();
    authenticate.mockReset();
  });

  it('restores a live session with no biometric prompt', async () => {
    invoke.mockResolvedValue({
      did: 'did:plc:abcdefghijklmnopqrstuvwx',
      pdsUrl: 'https://pds.example.com',
      accessExpiresAt: 1_720_003_600,
      refreshExpiresAt: 1_720_086_400,
      rotated: false,
    });

    const result = await ensureIdentitySession('did:plc:abcdefghijklmnopqrstuvwx');

    expect(authenticate).not.toHaveBeenCalled();
    expect(invoke).toHaveBeenCalledWith('ensure_identity_session', {
      did: 'did:plc:abcdefghijklmnopqrstuvwx',
    });
    expect(result.rotated).toBe(false);
  });

  it('surfaces a NEEDS_UNLOCK error so the caller can offer a passwordless unlock', async () => {
    invoke.mockRejectedValue({ code: 'NEEDS_UNLOCK', reason: 'HOST_CHANGED' });

    await expect(
      ensureIdentitySession('did:plc:abcdefghijklmnopqrstuvwx'),
    ).rejects.toMatchObject({ code: 'NEEDS_UNLOCK', reason: 'HOST_CHANGED' });
    expect(authenticate).not.toHaveBeenCalled();
  });
});
