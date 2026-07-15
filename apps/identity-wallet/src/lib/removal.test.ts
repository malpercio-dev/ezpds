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
});
