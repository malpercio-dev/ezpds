import { beforeEach, describe, expect, it, vi } from 'vitest';

const invoke = vi.fn();

vi.mock('@tauri-apps/api/core', () => ({
  get invoke() {
    return invoke;
  },
}));

import {
  requestIdentityRemoval,
  confirmIdentityRemoval,
  tombstoneIdentity,
} from './ipc';

// These lock the Rust command names + argument shapes: the wrappers are the only
// contract between the frontend and the `identity_removal.rs` `#[tauri::command]`s, so
// a rename on either side must break a test here rather than silently at runtime.
describe('identity-removal IPC wrappers', () => {
  const did = 'did:plc:abcdefghijklmnopqrstuvwx';

  beforeEach(() => {
    invoke.mockReset();
  });

  it('requestIdentityRemoval invokes request_identity_removal with the DID', async () => {
    invoke.mockResolvedValue(undefined);
    await requestIdentityRemoval(did);
    expect(invoke).toHaveBeenCalledWith('request_identity_removal', { did });
  });

  it('confirmIdentityRemoval passes did/password/token and returns the outcome', async () => {
    invoke.mockResolvedValue({ tombstoneCid: 'bafyfake', wasLastIdentity: true });
    const outcome = await confirmIdentityRemoval(did, 'hunter2', 'CODE123');
    expect(invoke).toHaveBeenCalledWith('confirm_identity_removal', {
      did,
      password: 'hunter2',
      token: 'CODE123',
    });
    expect(outcome).toEqual({ tombstoneCid: 'bafyfake', wasLastIdentity: true });
  });

  it('tombstoneIdentity invokes tombstone_identity with the DID', async () => {
    invoke.mockResolvedValue({ tombstoneCid: 'bafyfake', wasLastIdentity: false });
    const outcome = await tombstoneIdentity(did);
    expect(invoke).toHaveBeenCalledWith('tombstone_identity', { did });
    expect(outcome.wasLastIdentity).toBe(false);
  });

  // A did:web has no PLC tombstone, so the backend reports `tombstoneCid: null`. The
  // wrapper must surface that null verbatim — RemoveIdentityScreen switches on it to show
  // the "take your did.json down" epilogue instead of claiming a network-wide retirement.
  it('surfaces a null tombstoneCid for a did:web removal', async () => {
    const webDid = 'did:web:example.com';
    invoke.mockResolvedValue({ tombstoneCid: null, wasLastIdentity: true });
    const outcome = await confirmIdentityRemoval(webDid, 'hunter2', 'CODE123');
    expect(outcome.tombstoneCid).toBeNull();
    expect(outcome.wasLastIdentity).toBe(true);
  });
});
