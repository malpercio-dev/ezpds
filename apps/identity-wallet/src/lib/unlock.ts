/**
 * The one place a locked identity is reopened.
 *
 * Every authenticated screen hits the same wall: an operation rejects with `SESSION_LOCKED`
 * (or a pre-flight rejects with `NEEDS_UNLOCK`), and the screen has to turn that into a live
 * session before retrying. Until now each screen answered that with `sovereignLogin(did)`
 * inline, which silently assumed the identity's host offers passwordless sessions — true for
 * Custos, false for bsky.social and every other spec-compliant PDS.
 *
 * {@link unlockIdentity} is that single call, now aware of which unlock the host can actually
 * serve. Screens keep their existing shape (`catch SESSION_LOCKED → unlock → retry`); the
 * branch lives here, once.
 *
 * The password branch needs a UI the caller does not own, so it is inverted: a dialog rendered
 * once at the app root registers itself via {@link registerPasswordUnlockPrompt}, and this
 * module hands it the request and awaits the user's answer. That keeps `unlockIdentity`
 * callable from deep inside an async operation without every screen embedding a password form.
 *
 * This is a policy gate over IPC wrappers, not an `invoke()` wrapper itself, so it lives
 * outside `$lib/ipc` — the same reasoning that puts the biometric gate in `$lib/biometric.ts`.
 *
 * A successful unlock also re-fires push registration for the identity (fire-and-forget; see
 * {@link registerAfterUnlock}) — the unlock is the exact moment a registration that failed
 * `SESSION_LOCKED` at app open becomes repairable.
 */
import {
  getIdentityUnlockRoute,
  registerForNotifications,
  sovereignLogin,
  type UnlockRoute,
} from '$lib/ipc';
import {
  recordRegistrationFailure,
  recordRegistrationOutcome,
} from '$lib/notification-registration';

/** What the password dialog needs to render one unlock request. */
export type PasswordUnlockRequest = {
  did: string;
  /** The host being signed in to — shown so the user knows whose password is being asked for. */
  pdsUrl: string;
  /** Prefilled identifier from the DID document, when it has one. */
  handle: string | null;
};

/**
 * Resolves when the identity has been unlocked, rejects with {@link UNLOCK_CANCELLED} if the
 * user dismissed the prompt.
 */
export type PasswordUnlockPrompt = (request: PasswordUnlockRequest) => Promise<void>;

/**
 * The code a dismissed unlock rejects with. A cancellation is a decision, not a fault: screens
 * should return quietly rather than render an error, the same way they treat a cancelled
 * biometric prompt.
 */
export const UNLOCK_CANCELLED = 'UNLOCK_CANCELLED';

/** Was this rejection the user dismissing an unlock prompt? */
export const isUnlockCancelled = (error: unknown): boolean =>
  typeof error === 'object' &&
  error !== null &&
  (error as { code?: unknown }).code === UNLOCK_CANCELLED;

let prompt: PasswordUnlockPrompt | null = null;

/**
 * Register the app-level password dialog. Returns an unregister function for the component's
 * teardown, so a remount never leaves a stale handler bound to a destroyed component.
 */
export const registerPasswordUnlockPrompt = (handler: PasswordUnlockPrompt): (() => void) => {
  prompt = handler;
  return () => {
    if (prompt === handler) prompt = null;
  };
};

/**
 * Unlock `did`, using whichever route its host can serve.
 *
 * Resolves once the identity has a live session; the caller then retries the operation that
 * hit the lock. Rejects with the underlying IPC error, or with {@link UNLOCK_CANCELLED} if the
 * user dismissed the password prompt.
 *
 * `route` may be supplied by a caller that already fetched it (a screen rendering an unlock
 * affordance knows the route before the user taps it) to skip the extra round trip.
 */
export const unlockIdentity = async (did: string, route?: UnlockRoute): Promise<void> => {
  const resolved = route ?? (await getIdentityUnlockRoute(did));

  if (resolved.method === 'SOVEREIGN') {
    await sovereignLogin(did);
    registerAfterUnlock(did);
    return;
  }

  if (!prompt) {
    // A password host with no dialog mounted would otherwise fail as an opaque undefined call.
    throw { code: 'INVALID_RESPONSE', message: 'No password prompt is available.' };
  }
  await prompt({ did, pdsUrl: resolved.pdsUrl, handle: resolved.handle });
  registerAfterUnlock(did);
};

/**
 * Re-register for push the moment an unlock succeeds — fire-and-forget, never blocking the
 * operation the caller is about to retry.
 *
 * An unlock is exactly when a failed registration becomes repairable: the per-app-open pass
 * runs fire-and-forget with whatever session state it finds, so an identity that was locked at
 * launch stayed unregistered (and unable to receive a sign-in request push) until the NEXT
 * launch happened to find it unlocked. Doing it here closes that gap at the only moment the
 * session is known fresh. The outcome lands in the same ledger the app-open pass writes, so
 * Settings reflects the repair immediately.
 */
const registerAfterUnlock = (did: string): void => {
  void registerForNotifications(did)
    .then((outcome) => recordRegistrationOutcome(did, outcome))
    .catch((error) => recordRegistrationFailure(did, error));
};
