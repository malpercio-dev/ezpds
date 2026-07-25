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

  // Degraded exists to put every sweep state on screen at once, so the Status screen can
  // be read against all of them together. Crucially the two faults are carried by
  // DIFFERENT rows: staleness alone cannot express "the sweep is alive but skipping
  // work", so collapsing both onto one row would hide exactly the distinction the row
  // is there to draw.
  it('degraded health shows every sweep state at once', () => {
    const healthy = healthyServer(3);
    const degraded = healthyServer(3, { degraded: true });

    // Never ran.
    expect(degraded.sweeps.accountReaper).toBeNull();

    // Stale: completed much longer ago than the healthy fixture, and cleanly so — a
    // sweep that is dead reports no errors, because a failed pass records nothing.
    expect(degraded.sweeps.firehoseGc!.completedAt).toBeLessThan(
      healthy.sweeps.firehoseGc!.completedAt
    );
    expect(degraded.sweeps.firehoseGc!.errors).toBe(0);

    // Alive but leaking: a FRESH timestamp carrying errors — blob GC skipped an account
    // whose reconcile failed, so its blobs go uncollected until the fault is fixed.
    expect(degraded.sweeps.blobGc!.completedAt).toBe(healthy.sweeps.blobGc!.completedAt);
    expect(degraded.sweeps.blobGc!.errors).toBeGreaterThan(0);

    // A healthy readout reports no failures anywhere.
    expect(healthy.sweeps.blobGc!.errors).toBe(0);
  });

  it('device keys are deterministic per seed', () => {
    expect(fakeDeviceKey('a').keyId).toBe(fakeDeviceKey('a').keyId);
    expect(fakeDeviceKey('a').keyId).not.toBe(fakeDeviceKey('b').keyId);
  });
});
