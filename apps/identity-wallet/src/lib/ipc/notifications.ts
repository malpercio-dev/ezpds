import { invoke } from '@tauri-apps/api/core';
import type { UnlockReason } from './identity';

// ── Push notifications (the device half of the encrypted notification relay) ──
//
// The wallet registers a per-device P-256 key with each identity's Custos, which seals every
// push payload to it; a Notification Service Extension decrypts on arrival. Nothing here
// decrypts — these wrappers cover the two calls that keep the arrangement working: registering
// the device, and re-pinning the instance's sender keys.
//
// Re-pinning is the load-bearing one. A sender key the operator revokes stops being trusted on
// this device at its next contact with that Custos and not before, so `refreshNotificationSenderKeys`
// belongs on every successful contact — it is a security property with a cadence, not a cache
// refresh.
//
// Neither call is biometric-gated: no identity material is signed or exposed, and a prompt on
// the onboarding completion path would be a demand the user cannot connect to anything they did.

/** What a registration attempt actually did. */
export type RegistrationStatus =
  /** The server stored the registration and is minting a relay handle for it. */
  | 'REGISTERED'
  /**
   * No APNs token yet — the simulator never issues one, the user may not have granted
   * permission, and on a granted device it arrives asynchronously after launch. An ordinary
   * state, not a failure: the token-change callback re-registers when one shows up.
   */
  | 'AWAITING_APNS_TOKEN'
  /**
   * The identity's host serves no notification routes. Always true for a claimed identity on a
   * standard PDS, and for a Custos whose operator configured no relay.
   */
  | 'UNSUPPORTED';

export type RegistrationOutcome = {
  status: RegistrationStatus;
  /** The stable identifier this device registered under (the server keys rows on it). */
  deviceUuid: string;
  /** The device's notification `did:key`, or null when the attempt stopped before one was needed. */
  notificationKeyId: string | null;
};

/** One sender key this device trusts for a given host. */
export type SenderKey = {
  /** Instance-scoped key id — a sealed payload's envelope names which key sealed it. */
  kid: number;
  /** The P-256 `did:key` to verify the seal against. */
  publicKey: string;
};

/** The outcome of a re-pin. */
export type SenderKeyPinning = {
  /** The hosting server whose set was fetched (normalized). */
  host: string;
  /**
   * True when the server answered and the stored set was replaced wholesale — which is how a
   * revoked key stops being trusted. False when the host serves no notification routes, in which
   * case the stored set was left exactly as it was.
   */
  pinned: boolean;
  /** The set now pinned for this host. */
  keys: SenderKey[];
};

/** What this device holds, for the diagnostics surface. Public halves only. */
export type NotificationDiagnostics = {
  deviceUuid: string | null;
  notificationKeyId: string | null;
  hasApnsToken: boolean;
  /** Pinned sender keys per hosting server. Keyed by host because `kid` is instance-scoped:
   *  two Custos instances both start numbering at 1. */
  pinnedHosts: Record<string, SenderKey[]>;
};

export type NotificationsError =
  /** Run `unlockIdentity(did)` and retry. */
  | { code: 'SESSION_LOCKED'; reason: UnlockReason }
  | { code: 'RATE_LIMITED'; retryAfter: string | null }
  | { code: 'IDENTITY_NOT_FOUND'; message: string }
  | { code: 'KEY_GENERATION_FAILED'; message: string }
  | { code: 'KEYCHAIN_ERROR'; message: string }
  | { code: 'SERVER_ERROR'; status: number | null; message: string }
  | { code: 'NETWORK_ERROR'; message: string };

/**
 * Register this device for push on the identity's hosting Custos.
 *
 * Called at onboarding completion (post-promotion, so the account exists) and whenever the APNs
 * token changes. Idempotent server-side — it upserts on `(did, deviceUuid)` — so a caller never
 * has to track whether it already registered.
 *
 * Resolves rather than rejects for the two ordinary "no" answers (no token yet, host has no
 * relay), so a completion screen has nothing to catch on a simulator or a non-Custos host.
 */
export async function registerForNotifications(did: string): Promise<RegistrationOutcome> {
  return invoke<RegistrationOutcome>('register_for_notifications', { did });
}

/**
 * Re-fetch and re-pin the identity's host's sender-key set.
 *
 * Call on every successful contact with a Custos. That cadence is the design's
 * compromise-window property: until a device re-pins, a compromised sender key plus a colluding
 * relay can forge notification content for it.
 */
export async function refreshNotificationSenderKeys(did: string): Promise<SenderKeyPinning> {
  return invoke<SenderKeyPinning>('refresh_notification_sender_keys', { did });
}

/** What this device holds. Read-only, no network, no identity needed. */
export async function getNotificationDiagnostics(): Promise<NotificationDiagnostics> {
  return invoke<NotificationDiagnostics>('get_notification_diagnostics');
}
