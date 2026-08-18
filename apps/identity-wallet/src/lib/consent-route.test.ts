import { describe, expect, it, vi } from 'vitest';
import { resolveConsentIdentity, type ConsentIdentityCandidate } from './consent-route';

const REQUEST = 'poauth_abc123';

const alice: ConsentIdentityCandidate = { did: 'did:web:alice.example.com', handle: 'alice.example.com' };
const bob: ConsentIdentityCandidate = { did: 'did:plc:bobbobbobbobbobbobbobbob', handle: 'bob.pds.example' };
const nameless: ConsentIdentityCandidate = { did: 'did:plc:namelessnamelessnamele', handle: null };

/** A probe whose behavior is scripted per DID: a hint value means the server knows the
 *  request; `undefined` means that identity's server has never heard of it. */
function probe(known: Record<string, string | null>) {
  return vi.fn(async (did: string) => {
    if (did in known) return { loginHint: known[did] };
    throw { code: 'REQUEST_NOT_FOUND' };
  });
}

describe('resolveConsentIdentity', () => {
  it('a single identity answers without any network probe', async () => {
    const ask = probe({});
    await expect(resolveConsentIdentity(REQUEST, [alice], ask)).resolves.toBe(alice.did);
    expect(ask).not.toHaveBeenCalled();
  });

  it('no identities resolves to nothing', async () => {
    await expect(resolveConsentIdentity(REQUEST, [], probe({}))).resolves.toBeNull();
  });

  it('the identity whose server knows the request wins when it is the only holder', async () => {
    const ask = probe({ [bob.did]: null });
    await expect(resolveConsentIdentity(REQUEST, [alice, bob], ask)).resolves.toBe(bob.did);
    expect(ask).toHaveBeenCalledTimes(2);
  });

  it('a DID-form login hint singles out the bound identity among co-hosted ones', async () => {
    // Both identities live on one PDS, so both probes succeed — only the hint can decide.
    const ask = probe({ [alice.did]: alice.did, [bob.did]: alice.did });
    await expect(resolveConsentIdentity(REQUEST, [alice, bob], ask)).resolves.toBe(alice.did);
  });

  it('a handle-form login hint matches through the identity’s handle, prefixes and case aside', async () => {
    for (const hint of ['alice.example.com', '@Alice.Example.Com', 'at://alice.example.com']) {
      const ask = probe({ [alice.did]: hint, [bob.did]: hint });
      await expect(resolveConsentIdentity(REQUEST, [alice, bob], ask)).resolves.toBe(alice.did);
    }
  });

  it('an unhinted request on a shared server is genuinely ambiguous', async () => {
    const ask = probe({ [alice.did]: null, [bob.did]: null });
    await expect(resolveConsentIdentity(REQUEST, [alice, bob], ask)).resolves.toBeNull();
  });

  it('a hint naming an unmanaged account does not fall back to guessing among holders', async () => {
    // The request is bound to someone this wallet does not hold. Navigating anyway would set
    // the user up to approve as an account the server will refuse.
    const ask = probe({
      [alice.did]: 'did:web:someoneelse.example.com',
      [bob.did]: 'did:web:someoneelse.example.com',
    });
    await expect(resolveConsentIdentity(REQUEST, [alice, bob], ask)).resolves.toBeNull();
  });

  it('a hint-bound request still resolves when only the bound server knows it', async () => {
    const ask = probe({ [alice.did]: alice.did });
    await expect(resolveConsentIdentity(REQUEST, [alice, bob, nameless], ask)).resolves.toBe(
      alice.did
    );
  });

  it('no server knowing the request resolves to nothing', async () => {
    await expect(resolveConsentIdentity(REQUEST, [alice, bob], probe({}))).resolves.toBeNull();
  });

  it('an identity with no local handle still matches a DID-form hint', async () => {
    const ask = probe({ [nameless.did]: nameless.did, [alice.did]: nameless.did });
    await expect(resolveConsentIdentity(REQUEST, [alice, nameless], ask)).resolves.toBe(
      nameless.did
    );
  });
});
