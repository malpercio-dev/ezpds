import { describe, it, expect, vi, beforeEach } from 'vitest';

// Drive the outbound-migration source-auth wrapper without a Tauri runtime: mock the IPC
// bridge and script each command's outcome by name. The auth-session plugin rejects with
// plain strings — the exact sentinel "user_cancelled" for a dismissed sheet, descriptive
// text for real failures — and the wrapper must map only the former to the "cancelled" case.
// (The claim flow's source login is password-based — `authenticateSourcePds` — and has no
// auth-session dance to classify, so it isn't covered here.)
const invoke = vi.fn();
vi.mock('@tauri-apps/api/core', () => ({
  get invoke() {
    return invoke;
  },
}));

import { startSourceAuth } from './ipc';

const PREPARED = {
  authUrl: 'https://pds.example/oauth/authorize?request_uri=abc',
  callbackScheme: 'org.obsign.identitywallet',
};
const CALLBACK_URL = 'org.obsign.identitywallet:/oauth/callback?code=c&state=s';

function scriptInvoke(outcomes: Record<string, () => Promise<unknown>>) {
  invoke.mockImplementation((cmd: string) => {
    const outcome = outcomes[cmd];
    if (!outcome) return Promise.reject(new Error(`unexpected invoke: ${cmd}`));
    return outcome();
  });
}

beforeEach(() => {
  invoke.mockReset();
});

describe('startSourceAuth', () => {
  it('runs prepare → auth session → complete, passing the DID and callback URL through', async () => {
    scriptInvoke({
      prepare_source_auth: () => Promise.resolve(PREPARED),
      'plugin:auth-session|start': () => Promise.resolve(CALLBACK_URL),
      complete_source_auth: () => Promise.resolve(undefined),
    });

    await expect(startSourceAuth('did:plc:abc')).resolves.toBeUndefined();
    expect(invoke).toHaveBeenCalledWith('complete_source_auth', {
      did: 'did:plc:abc',
      callbackUrl: CALLBACK_URL,
    });
  });

  it('maps a dismissed auth sheet to SOURCE_AUTH_FAILED and never calls complete', async () => {
    scriptInvoke({
      prepare_source_auth: () => Promise.resolve(PREPARED),
      'plugin:auth-session|start': () => Promise.reject('user_cancelled'),
    });

    await expect(startSourceAuth('did:plc:abc')).rejects.toEqual({
      code: 'SOURCE_AUTH_FAILED',
      message: 'auth session cancelled',
    });
    expect(invoke).not.toHaveBeenCalledWith('complete_source_auth', expect.anything());
  });

  it('maps a non-cancel auth-session failure to NETWORK_ERROR carrying the plugin message', async () => {
    scriptInvoke({
      prepare_source_auth: () => Promise.resolve(PREPARED),
      'plugin:auth-session|start': () => Promise.reject('No browser available to handle authentication'),
    });

    await expect(startSourceAuth('did:plc:abc')).rejects.toEqual({
      code: 'NETWORK_ERROR',
      message: 'No browser available to handle authentication',
    });
  });

  it('passes prepare failures through unchanged (already typed by Rust)', async () => {
    scriptInvoke({
      prepare_source_auth: () => Promise.reject({ code: 'SOURCE_AUTH_FAILED', message: 'PAR failed' }),
    });

    await expect(startSourceAuth('did:plc:abc')).rejects.toEqual({
      code: 'SOURCE_AUTH_FAILED',
      message: 'PAR failed',
    });
    expect(invoke).not.toHaveBeenCalledWith('plugin:auth-session|start', expect.anything());
  });
});
