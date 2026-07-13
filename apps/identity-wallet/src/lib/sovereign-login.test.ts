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

import { sovereignLogin } from './ipc';

describe('sovereignLogin', () => {
  beforeEach(() => {
    invoke.mockReset();
    authenticate.mockReset();
  });

  it('invokes Rust only after biometric authentication succeeds', async () => {
    authenticate.mockResolvedValue(undefined);
    invoke.mockResolvedValue({
      did: 'did:plc:abcdefghijklmnopqrstuvwx',
      pdsUrl: 'https://pds.example.com',
      accessExpiresAt: 1_720_003_600,
      refreshExpiresAt: 1_720_086_400,
    });

    await sovereignLogin('did:plc:abcdefghijklmnopqrstuvwx');

    expect(authenticate).toHaveBeenCalledTimes(1);
    expect(invoke).toHaveBeenCalledWith('sovereign_login', {
      did: 'did:plc:abcdefghijklmnopqrstuvwx',
    });
    expect(authenticate.mock.invocationCallOrder[0]).toBeLessThan(
      invoke.mock.invocationCallOrder[0],
    );
  });

  it('performs no IPC or network-capable work when biometric authentication is cancelled', async () => {
    authenticate.mockRejectedValue(new Error('user cancelled'));

    await expect(sovereignLogin('did:plc:abcdefghijklmnopqrstuvwx')).rejects.toThrow(
      'user cancelled',
    );
    expect(invoke).not.toHaveBeenCalled();
  });
});
