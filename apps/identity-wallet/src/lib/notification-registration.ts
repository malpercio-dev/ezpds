// What happened the last time each identity tried to register this device for push.
//
// Registration is fire-and-forget by design (once per app open per identity, plus each
// onboarding completion), which means its failures have nowhere to land: a `console.warn` on
// a phone is invisible, and the notification-health surface reads only the Notification
// Service Extension's breadcrumbs — a log of pushes that *arrived* broken, which can never
// represent "nothing can arrive". An identity whose registration fails on every launch
// therefore looked exactly like perfect health. This module is the missing ledger: the
// callers that fire a registration record its outcome here, and Settings reads it back.
//
// Session-scoped on purpose. The record answers "did registration work *this launch*", and a
// persisted copy would only ever report a staler version of what the next launch's pass is
// about to re-establish anyway. The store holds one newest-wins record per DID.
//
// The wording lives here rather than in the screen for the same reason
// `notification-health.ts`'s does: every branch is pure over its inputs, so the sentence for
// a failure mode is testable without a device, a session, or a failing server.

import { writable } from 'svelte/store';
import type { RegistrationOutcome } from '$lib/ipc';

/** The newest registration result for one identity. */
export type RegistrationRecord =
  | { kind: 'outcome'; status: RegistrationOutcome['status'] }
  | { kind: 'error'; code: string };

/**
 * Newest-wins record per DID, for the launch that is currently running.
 *
 * Write-backs are immutable replacements (never in-place mutation) so Svelte's store
 * subscribers actually fire.
 */
export const registrationRecords = writable<Record<string, RegistrationRecord>>({});

/** Record what a completed registration attempt reported. */
export function recordRegistrationOutcome(did: string, outcome: RegistrationOutcome): void {
  registrationRecords.update((records) => ({
    ...records,
    [did]: { kind: 'outcome', status: outcome.status },
  }));
}

/**
 * Record a registration attempt that rejected.
 *
 * The error is reduced to its `code` at the boundary: the codes are the wire contract
 * (`NotificationsError` in `$lib/ipc`), and anything without one — a thrown string, an IPC
 * transport fault — is recorded as `UNKNOWN` rather than dropped, because the attempt that
 * cannot be classified is still an attempt that failed.
 */
export function recordRegistrationFailure(did: string, error: unknown): void {
  const code =
    typeof error === 'object' && error !== null && typeof (error as { code?: unknown }).code === 'string'
      ? (error as { code: string }).code
      : 'UNKNOWN';
  registrationRecords.update((records) => ({
    ...records,
    [did]: { kind: 'error', code },
  }));
}

/** How loudly one identity's registration state should read. Same two-level scale as
 *  `notification-health.ts`, and for the same reason: nothing here can cost an identity. */
export type RegistrationHealthLevel = 'quiet' | 'info' | 'attention';

export type RegistrationHealth = {
  level: RegistrationHealthLevel;
  /** One line naming the state. Never a colour, never an icon alone. */
  headline: string;
  /** What it means, in the user's terms. */
  detail: string;
  /** What to do, or null when there is genuinely nothing to do. */
  advice: string | null;
};

/**
 * The sentence for one identity's newest record.
 *
 * `undefined` (no attempt recorded this launch) is a real state, not an error: Settings can
 * open before the app-open registration pass has finished, and claiming either health or
 * failure before an attempt has reported would be inventing a result.
 */
export function describeRegistration(record: RegistrationRecord | undefined): RegistrationHealth {
  if (record === undefined) {
    return {
      level: 'info',
      headline: 'Not checked yet',
      detail: 'Registration runs shortly after Obsign opens; this identity has not reported yet.',
      advice: null,
    };
  }

  return record.kind === 'outcome' ? describeOutcome(record.status) : describeErrorCode(record.code);
}

function describeOutcome(status: RegistrationOutcome['status']): RegistrationHealth {
  switch (status) {
    case 'REGISTERED':
      return {
        level: 'quiet',
        headline: 'Registered for notifications',
        detail: 'This identity’s server can send sealed notifications to this iPhone.',
        advice: null,
      };
    case 'AWAITING_APNS_TOKEN':
      return {
        level: 'info',
        headline: 'Waiting for a push token from iOS',
        detail:
          'iOS has not issued this device a push token yet. It usually arrives on its own shortly after launch.',
        advice: 'If this persists, check that notifications are allowed for Obsign in iOS Settings.',
      };
    case 'UNSUPPORTED':
      return {
        level: 'info',
        headline: 'This identity’s server doesn’t send notifications',
        detail:
          'Its hosting server has no notification relay configured — ordinary for an identity hosted outside Custos.',
        advice: null,
      };
  }
}

function describeErrorCode(code: string): RegistrationHealth {
  switch (code) {
    case 'SESSION_LOCKED':
      return {
        level: 'attention',
        headline: 'Locked — not registered for notifications',
        detail:
          'This identity’s session needs an unlock before its server can register this iPhone, so sign-in requests and other notifications cannot reach you.',
        advice: 'Open this identity and unlock it — registration then happens on its own.',
      };
    case 'NETWORK_ERROR':
      return {
        level: 'info',
        headline: 'Couldn’t reach the server last time',
        detail: 'The registration attempt could not connect. It retries the next time Obsign opens.',
        advice: null,
      };
    case 'RATE_LIMITED':
      return {
        level: 'info',
        headline: 'The server asked this device to slow down',
        detail: 'Registration was rate limited. It retries the next time Obsign opens.',
        advice: null,
      };
    default:
      return {
        level: 'attention',
        headline: 'Registration failed',
        detail:
          'The last attempt to register this iPhone for notifications did not succeed, so notifications for this identity may not arrive.',
        // The code is the diagnostic seam (ADR-0031): shown as-is, subordinate to the sentence.
        advice: `If this keeps happening, export diagnostics and report it (code ${code}).`,
      };
  }
}
