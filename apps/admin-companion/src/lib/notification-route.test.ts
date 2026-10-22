import { describe, it, expect } from 'vitest';
import { notificationHref, serverKey } from './notification-route';
import type { Pairing, PendingNotificationRoute } from './ipc';

const pairing = (id: string, relayUrl: string): Pairing => ({
  id,
  nickname: id,
  relayUrl,
  deviceId: `dev-${id}`,
  deviceLabel: 'console',
  notificationSenderKeys: [],
});

const PAIRINGS = [
  pairing('staging', 'https://staging.pds.example/'),
  pairing('prod', 'https://pds.example'),
];

const flagged = (over: Partial<PendingNotificationRoute> = {}): PendingNotificationRoute => ({
  kind: 'accounts_flagged',
  server: 'https://pds.example',
  screen: 'accounts',
  did: null,
  ...over,
});

describe('notificationHref', () => {
  it('opens the Accounts screen pinned to the pairing whose relay the alert names', () => {
    expect(notificationHref(flagged(), PAIRINGS)).toBe('/accounts?server=prod');
  });

  it('matches the server by normalized URL, never by nickname or exact spelling', () => {
    // Pairing stored with a trailing slash; server advertised without, in caps.
    expect(notificationHref(flagged({ server: 'HTTPS://Staging.pds.example' }), PAIRINGS)).toBe(
      '/accounts?server=staging',
    );
    expect(serverKey(' https://A.example/// ')).toBe('https://a.example');
  });

  it('opens the account detail when the alert concerns one account', () => {
    expect(
      notificationHref(
        flagged({ kind: 'storage_cap_approaching', did: 'did:plc:abc' }),
        PAIRINGS,
      ),
    ).toBe('/account?server=prod&did=did%3Aplc%3Aabc');
  });

  it('routes nowhere for a server this device is not paired with', () => {
    expect(notificationHref(flagged({ server: 'https://other.example' }), PAIRINGS)).toBeNull();
    expect(notificationHref(flagged({ server: '' }), PAIRINGS)).toBeNull();
    expect(notificationHref(flagged(), [])).toBeNull();
  });

  it('routes nowhere for a screen this build does not know', () => {
    expect(notificationHref(flagged({ screen: 'settings' }), PAIRINGS)).toBeNull();
    expect(notificationHref(flagged({ screen: '../pair' }), PAIRINGS)).toBeNull();
    expect(notificationHref(flagged({ screen: null }), PAIRINGS)).toBeNull();
  });
});
