import { describe, it, expect } from 'vitest';
import {
  emptyWalletState,
  seedIdentity,
  makeDidDoc,
  findIdentity,
  upsertIdentity,
  fakeDeviceKeyId,
  fakePlcDid,
} from './state';
import { extractHandle, extractPdsFromPlcDoc } from '$lib/did-doc-utils';

describe('wallet harness state', () => {
  it('fresh state is empty and unconfigured', () => {
    const state = emptyWalletState();
    expect(state.identities).toEqual([]);
    expect(state.pdsUrl).toBeNull();
    expect(state.biometricEnabled).toBe(true);
  });

  it('seeds a device-key-root identity by default', () => {
    const id = seedIdentity({ handle: 'alice.test' });
    expect(id.rotationKeys[0]).toBe(id.deviceKeyId);
  });

  it('places the device key off-root when deviceKeyIsRoot is false', () => {
    const id = seedIdentity({ handle: 'bob.test', deviceKeyIsRoot: false });
    expect(id.rotationKeys[0]).not.toBe(id.deviceKeyId);
    expect(id.rotationKeys).toContain(id.deviceKeyId);
  });

  it('builds a PLC-format DID doc the home screen can parse', () => {
    // The home card reads handle from alsoKnownAs and PDS from services.atproto_pds —
    // these are the real extractors, so the fake must satisfy them exactly.
    const id = seedIdentity({ handle: 'alice.test', pdsUrl: 'https://pds.example' });
    const doc = makeDidDoc(id);
    expect(extractHandle(doc)).toBe('alice.test');
    expect(extractPdsFromPlcDoc(doc)).toBe('https://pds.example');
    expect(Array.isArray(doc.rotationKeys)).toBe(true);
  });

  it('upsert is idempotent by DID', () => {
    const state = emptyWalletState();
    const id = seedIdentity({ handle: 'alice.test' });
    upsertIdentity(state, id);
    upsertIdentity(state, { ...id, handle: 'alice2.test' });
    expect(state.identities).toHaveLength(1);
    expect(findIdentity(state, id.did)?.handle).toBe('alice2.test');
  });

  it('key/DID generators are deterministic per seed', () => {
    expect(fakeDeviceKeyId('x')).toBe(fakeDeviceKeyId('x'));
    expect(fakePlcDid('x')).toBe(fakePlcDid('x'));
    expect(fakeDeviceKeyId('x')).not.toBe(fakeDeviceKeyId('y'));
  });
});
