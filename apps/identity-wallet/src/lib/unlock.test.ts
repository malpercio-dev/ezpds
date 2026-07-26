import { beforeEach, describe, expect, it, vi } from 'vitest';

const getIdentityUnlockRoute = vi.fn();
const sovereignLogin = vi.fn();

vi.mock('$lib/ipc', () => ({
  getIdentityUnlockRoute: (did: string) => getIdentityUnlockRoute(did),
  sovereignLogin: (did: string) => sovereignLogin(did),
}));

const {
  unlockIdentity,
  registerPasswordUnlockPrompt,
  isUnlockCancelled,
  UNLOCK_CANCELLED,
} = await import('./unlock');

const DID = 'did:plc:abcdefghijklmnopqrstuvwx';

const sovereignRoute = { method: 'SOVEREIGN' as const, pdsUrl: 'https://obsign.org', handle: null };
const passwordRoute = {
  method: 'PASSWORD' as const,
  pdsUrl: 'https://bsky.social',
  handle: 'alice.bsky.social',
};

describe('unlockIdentity', () => {
  let unregister: (() => void) | null = null;

  beforeEach(() => {
    getIdentityUnlockRoute.mockReset();
    sovereignLogin.mockReset().mockResolvedValue(undefined);
    unregister?.();
    unregister = null;
  });

  it('keeps the passwordless route on a host that advertises sovereign sessions', async () => {
    getIdentityUnlockRoute.mockResolvedValue(sovereignRoute);
    const prompt = vi.fn().mockResolvedValue(undefined);
    unregister = registerPasswordUnlockPrompt(prompt);

    await unlockIdentity(DID);

    expect(sovereignLogin).toHaveBeenCalledWith(DID);
    expect(prompt).not.toHaveBeenCalled();
  });

  it('routes a standard-lexicon host to the password prompt, naming the host', async () => {
    getIdentityUnlockRoute.mockResolvedValue(passwordRoute);
    const prompt = vi.fn().mockResolvedValue(undefined);
    unregister = registerPasswordUnlockPrompt(prompt);

    await unlockIdentity(DID);

    expect(sovereignLogin).not.toHaveBeenCalled();
    expect(prompt).toHaveBeenCalledWith({
      did: DID,
      pdsUrl: 'https://bsky.social',
      handle: 'alice.bsky.social',
    });
  });

  it('accepts a pre-fetched route instead of re-asking the backend', async () => {
    const prompt = vi.fn().mockResolvedValue(undefined);
    unregister = registerPasswordUnlockPrompt(prompt);

    await unlockIdentity(DID, passwordRoute);

    expect(getIdentityUnlockRoute).not.toHaveBeenCalled();
    expect(prompt).toHaveBeenCalledOnce();
  });

  it('propagates a dismissed prompt as a recognizable cancellation', async () => {
    getIdentityUnlockRoute.mockResolvedValue(passwordRoute);
    unregister = registerPasswordUnlockPrompt(() =>
      Promise.reject({ code: UNLOCK_CANCELLED }),
    );

    const error = await unlockIdentity(DID).catch((e) => e);

    expect(isUnlockCancelled(error)).toBe(true);
    // A cancellation must stay distinguishable from a real failure, or every screen renders
    // "something went wrong" when the user simply changed their mind.
    expect(isUnlockCancelled({ code: 'NETWORK_ERROR' })).toBe(false);
    expect(isUnlockCancelled(new Error('boom'))).toBe(false);
  });

  // The single-slot invariant itself lives in PasswordUnlockDialog (there is one dialog, so it
  // owns the slot), and this repo has no Svelte component-test setup — `$lib` tests are
  // pure-logic only. What is covered here is the half that lives in this module: that a prompt
  // superseding its predecessor propagates out to the *first* caller as a cancellation rather
  // than leaving its `await` pending forever.
  it('propagates a superseded prompt to the first caller as a cancellation', async () => {
    getIdentityUnlockRoute.mockResolvedValue(passwordRoute);
    // Stand in for the real dialog: one prompt slot, and taking it cancels whoever held it.
    let held: { reject: (reason: unknown) => void } | null = null;
    unregister = registerPasswordUnlockPrompt(
      () =>
        new Promise<void>((_resolve, reject) => {
          held?.reject({ code: UNLOCK_CANCELLED });
          held = { reject };
        }),
    );

    const first = unlockIdentity(DID);
    const firstSettled = first.then(
      () => 'resolved',
      (e) => e,
    );
    await Promise.resolve();
    void unlockIdentity(DID).catch(() => {});

    // Without the hand-off the assertion below never runs — the promise stays pending and the
    // test times out, which is exactly the user-visible symptom (an operation that never ends).
    expect(isUnlockCancelled(await firstSettled)).toBe(true);
  });

  it('fails loudly rather than silently when no prompt is mounted', async () => {
    getIdentityUnlockRoute.mockResolvedValue(passwordRoute);

    await expect(unlockIdentity(DID)).rejects.toMatchObject({ code: 'INVALID_RESPONSE' });
  });

  it('unregistering restores the no-prompt state without clobbering a newer handler', async () => {
    getIdentityUnlockRoute.mockResolvedValue(passwordRoute);
    const first = vi.fn().mockResolvedValue(undefined);
    const second = vi.fn().mockResolvedValue(undefined);

    const dropFirst = registerPasswordUnlockPrompt(first);
    unregister = registerPasswordUnlockPrompt(second);
    // A remount registers before the old component tears down; the stale unregister must not
    // detach the live handler.
    dropFirst();

    await unlockIdentity(DID);

    expect(first).not.toHaveBeenCalled();
    expect(second).toHaveBeenCalledOnce();
  });
});
