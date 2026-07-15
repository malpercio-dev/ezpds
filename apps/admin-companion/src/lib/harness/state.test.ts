import { describe, it, expect } from 'vitest';
import {
  emptyAdminState,
  seedRelay,
  toPairing,
  findRelay,
  activeRelay,
  healthyServer,
  fakeDeviceKey,
} from './state';

describe('admin harness state', () => {
  it('fresh state is unpaired with a device key', () => {
    const state = emptyAdminState();
    expect(state.relays).toHaveLength(0);
    expect(state.active).toBeNull();
    expect(state.deviceKey.keyId.startsWith('did:key:')).toBe(true);
  });

  it('seeds a relay whose first device is "this device"', () => {
    const relay = seedRelay({ nickname: 'staging', relayUrl: 'https://s.relay' });
    expect(relay.deviceId).toBe(relay.devices[0].id);
    expect(relay.devices.length).toBeGreaterThanOrEqual(2);
  });

  it('toPairing projects the relay to the wire Pairing shape', () => {
    const relay = seedRelay({ nickname: 'staging', relayUrl: 'https://s.relay' });
    const pairing = toPairing(relay);
    expect(pairing).toMatchObject({
      id: relay.pairingId,
      nickname: 'staging',
      relayUrl: 'https://s.relay',
      deviceId: relay.deviceId,
    });
  });

  it('findRelay / activeRelay resolve by id and active pointer', () => {
    const state = emptyAdminState();
    const relay = seedRelay({ nickname: 'staging', relayUrl: 'https://s.relay' });
    state.relays = [relay];
    state.active = relay.pairingId;
    expect(findRelay(state, relay.pairingId)).toBe(relay);
    expect(activeRelay(state)).toBe(relay);
  });

  it('degraded health has a stale sweep and no reaper run', () => {
    const healthy = healthyServer(3);
    const degraded = healthyServer(3, { degraded: true });
    expect(degraded.sweeps.accountReaper).toBeNull();
    // The degraded blobGc completed much longer ago than the healthy one.
    expect(degraded.sweeps.blobGc!.completedAt).toBeLessThan(healthy.sweeps.blobGc!.completedAt);
  });

  it('device keys are deterministic per seed', () => {
    expect(fakeDeviceKey('a').keyId).toBe(fakeDeviceKey('a').keyId);
    expect(fakeDeviceKey('a').keyId).not.toBe(fakeDeviceKey('b').keyId);
  });
});
