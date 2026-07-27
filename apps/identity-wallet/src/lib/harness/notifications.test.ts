import { describe, it, expect } from 'vitest';
import { buildRegistry } from './registry';
import { scenarios } from './scenarios';
import type { WalletState } from './state';
import type {
  NotificationDiagnostics,
  RegistrationOutcome,
  SenderKeyPinning,
} from '$lib/ipc';

/**
 * Drives the push-notification flow logic through the fake IPC seam — the half of MM-419 a
 * browser can actually exercise. (The Keychain half, including the protection class each slot
 * lands under, is asserted in Rust against the in-memory double; a browser has no Keychain and
 * no APNs, and pretending otherwise would be theatre.)
 *
 * What is checked here is the flow's behaviour in the three states the wallet is genuinely in:
 * no APNs token (a simulator, a denied prompt, or a token that has not arrived yet), a host with
 * no relay, and a working Custos — plus the property the whole design rests on, that a re-pin
 * *replaces* a host's key set rather than merging into it.
 */
describe('wallet harness push notifications', () => {
  /** Give the fake device an APNs token, the way a real device gets one after launch. */
  function withApnsToken(state: WalletState): WalletState {
    state.notifications.apnsToken = 'aabbcc00';
    return state;
  }

  it('reports the token-less device rather than failing, and pins nothing', () => {
    const state = scenarios['one-identity']();
    const registry = buildRegistry(state);
    const did = (registry.list_identities({}) as string[])[0];

    const outcome = registry.register_for_notifications({ did }) as RegistrationOutcome;

    // A simulator has no APNs, and neither does a browser. Onboarding must be able to call this
    // unconditionally, so the answer is an outcome and not a rejection.
    expect(outcome.status).toBe('AWAITING_APNS_TOKEN');
    expect(outcome.deviceUuid).not.toBe('');
    expect(
      outcome.notificationKeyId,
      'no key is minted for a registration that cannot happen — it would pin the device to a key its host never heard of',
    ).toBeNull();
    expect(state.notifications.registeredDids).toEqual([]);
    expect(state.notifications.pinnedHosts).toEqual({});
  });

  it('registers against a Custos and re-pins on the same contact', () => {
    const state = withApnsToken(scenarios['one-identity']());
    const registry = buildRegistry(state);
    const did = (registry.list_identities({}) as string[])[0];
    const host = state.identities[0].pdsUrl;

    const outcome = registry.register_for_notifications({ did }) as RegistrationOutcome;

    expect(outcome.status).toBe('REGISTERED');
    expect(outcome.notificationKeyId).toMatch(/^did:key:z/);
    expect(state.notifications.registeredDids).toEqual([did]);
    // The moment a device becomes reachable is the moment it needs the keys to verify what
    // arrives, so registration re-pins rather than leaving a gap until the next contact.
    expect(state.notifications.pinnedHosts[host]).toHaveLength(1);
  });

  it('is idempotent — the server upserts, so a caller never has to track whether it already registered', () => {
    const state = withApnsToken(scenarios['one-identity']());
    const registry = buildRegistry(state);
    const did = (registry.list_identities({}) as string[])[0];

    registry.register_for_notifications({ did });
    registry.register_for_notifications({ did });

    expect(state.notifications.registeredDids).toEqual([did]);
  });

  it('steps aside on a host that runs no relay, without calling it a failure', () => {
    // `foreign-pds` is a spec-compliant non-Custos host: it advertises no capabilities, which is
    // exactly the shape whose real notification routes answer 501.
    const state = withApnsToken(scenarios['foreign-pds']());
    state.identities = scenarios['one-identity']().identities;
    const registry = buildRegistry(state);
    const did = (registry.list_identities({}) as string[])[0];

    const outcome = registry.register_for_notifications({ did }) as RegistrationOutcome;
    expect(outcome.status).toBe('UNSUPPORTED');
    expect(state.notifications.registeredDids).toEqual([]);

    // And a re-pin against it leaves whatever was pinned alone: switching the feature off is not
    // a revocation, and clearing on it would strip every device that checked in during an outage.
    state.notifications.pinnedHosts[state.identities[0].pdsUrl] = [
      { kid: 9, publicKey: 'did:key:zPreviouslyPinned' },
    ];
    const pinning = registry.refresh_notification_sender_keys({ did }) as SenderKeyPinning;
    expect(pinning.pinned).toBe(false);
    expect(pinning.keys).toEqual([{ kid: 9, publicKey: 'did:key:zPreviouslyPinned' }]);
  });

  it('replaces a host key set wholesale on re-pin — the revocation mechanism', () => {
    const state = withApnsToken(scenarios['one-identity']());
    const registry = buildRegistry(state);
    const did = (registry.list_identities({}) as string[])[0];
    const host = state.identities[0].pdsUrl;

    state.notifications.pinnedHosts[host] = [
      { kid: 1, publicKey: 'did:key:zStale' },
      { kid: 2, publicKey: 'did:key:zRevoked' },
    ];

    const pinning = registry.refresh_notification_sender_keys({ did }) as SenderKeyPinning;

    expect(pinning.pinned).toBe(true);
    expect(pinning.host).toBe(host);
    expect(
      state.notifications.pinnedHosts[host].map((k) => k.publicKey),
      'a key the server stopped publishing is the one it revoked — merging would keep trusting it',
    ).not.toContain('did:key:zRevoked');
    expect(state.notifications.pinnedHosts[host]).toEqual(pinning.keys);
  });

  it('reports diagnostics without inventing state or leaking the private half', () => {
    const state = scenarios['one-identity']();
    const registry = buildRegistry(state);
    const did = (registry.list_identities({}) as string[])[0];

    const bare = registry.get_notification_diagnostics({}) as NotificationDiagnostics;
    expect(bare.hasApnsToken).toBe(false);
    expect(bare.notificationKeyId).toBeNull();
    expect(bare.pinnedHosts).toEqual({});

    withApnsToken(state);
    registry.register_for_notifications({ did });

    const live = registry.get_notification_diagnostics({}) as NotificationDiagnostics;
    expect(live.hasApnsToken).toBe(true);
    expect(live.notificationKeyId).toMatch(/^did:key:z/);
    expect(Object.keys(live.pinnedHosts)).toEqual([state.identities[0].pdsUrl]);
    expect(
      JSON.stringify(live),
      'diagnostics are shareable — the raw APNs token must not ride along',
    ).not.toContain('aabbcc00');
  });

  it('refuses an unknown identity rather than registering a DID this wallet does not manage', () => {
    const registry = buildRegistry(withApnsToken(scenarios['one-identity']()));
    expect(() => registry.register_for_notifications({ did: 'did:plc:nosuchidentity' })).toThrow();
    expect(() =>
      registry.refresh_notification_sender_keys({ did: 'did:plc:nosuchidentity' }),
    ).toThrow();
  });
});
