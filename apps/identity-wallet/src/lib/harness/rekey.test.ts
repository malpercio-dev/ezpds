import { describe, it, expect } from 'vitest';
import { buildRegistry } from './registry';
import { scenarios } from './scenarios';
import { fakeRecoveryKeyId, seedIdentity } from './state';
import { isOldModelRecovery } from '$lib/did-doc-utils';
import type { RekeyPreview, RekeyResult } from '$lib/ipc';

/**
 * Drives the MM-411 old-model re-key through the fake end to end, mirroring the ACs:
 *  - an old-model did:plc identity upgrades to a 3-key rotationKeys array;
 *  - a did:web identity and a new-model identity are never eligible and reject the build;
 *  - interrupt-and-resume converges on the same terminal state.
 */
describe('wallet harness re-key (MM-411)', () => {
  it('detects the old model from the stored doc and hides the prompt otherwise', () => {
    const state = scenarios['rekey-mixed']();
    const registry = buildRegistry(state);
    const dids = registry.list_identities({}) as string[];

    for (const did of dids) {
      const doc = registry.get_stored_did_doc({ did }) as Record<string, unknown>;
      const eligible = isOldModelRecovery(did, doc);
      if (did.startsWith('did:web:')) {
        expect(eligible, 'did:web is never old-model').toBe(false);
      } else if ((doc.rotationKeys as string[]).length >= 3) {
        expect(eligible, 'new-model (3-key) is never old-model').toBe(false);
      } else {
        expect(eligible, 'old-model (2-key) did:plc is eligible').toBe(true);
      }
    }
  });

  it('runs the full re-key: 3 rotation keys, new Share 3, staging torn down (AC1)', () => {
    const state = scenarios['rekey-eligible']();
    const registry = buildRegistry(state);
    const did = (registry.list_identities({}) as string[])[0];

    // Old model to start: exactly [device, PDS], no re-key in progress.
    const before = registry.get_stored_did_doc({ did }) as Record<string, unknown>;
    expect((before.rotationKeys as string[]).length).toBe(2);
    expect(registry.rekey_in_progress_cmd({ did })).toBe(false);

    const preview = registry.build_rekey_cmd({ did }) as RekeyPreview;
    // The diff is additive — the recovery key is added, nothing is removed.
    expect(preview.diff.addedKeys).toEqual([fakeRecoveryKeyId(did)]);
    expect(preview.diff.removedKeys).toEqual([]);
    expect(registry.rekey_in_progress_cmd({ did })).toBe(true);

    const result = registry.submit_rekey_cmd({ did }) as RekeyResult;
    expect(result.share3.length).toBeGreaterThan(0);
    expect(result.share3Words.split(' ').length).toBe(42);

    // The doc now carries [device, recovery, PDS] — device stayed at [0].
    const after = registry.get_stored_did_doc({ did }) as Record<string, unknown>;
    const keys = after.rotationKeys as string[];
    expect(keys.length).toBe(3);
    expect(keys[0]).toBe((before.rotationKeys as string[])[0]);
    expect(keys[1]).toBe(fakeRecoveryKeyId(did));

    // Confirming the new Share 3 tears down staging; the identity is no longer eligible.
    registry.confirm_rekey_cmd({ did });
    expect(registry.rekey_in_progress_cmd({ did })).toBe(false);
    expect(isOldModelRecovery(did, after)).toBe(false);
  });

  it('never prompts or re-keys a new-model identity (AC2)', () => {
    const state = scenarios['rekey-mixed']();
    const registry = buildRegistry(state);
    // The new-model identity is the did:plc one whose doc already carries 3 rotation keys.
    const did = (registry.list_identities({}) as string[]).find((d) => {
      if (d.startsWith('did:web:')) return false;
      const doc = registry.get_stored_did_doc({ did: d }) as Record<string, unknown>;
      return (doc.rotationKeys as string[]).length === 3;
    }) as string;

    expect(registry.rekey_in_progress_cmd({ did })).toBe(false);
    expect(() => registry.build_rekey_cmd({ did })).toThrow();
    try {
      registry.build_rekey_cmd({ did });
    } catch (e) {
      expect((e as { code: string }).code).toBe('ALREADY_REKEYED');
    }
  });

  it('never prompts or re-keys a did:web identity (AC2)', () => {
    const state = scenarios['rekey-mixed']();
    const registry = buildRegistry(state);
    const did = 'did:web:web.example.com';

    try {
      registry.build_rekey_cmd({ did });
      throw new Error('build should have rejected did:web');
    } catch (e) {
      expect((e as { code: string }).code).toBe('NOT_DID_PLC');
    }
  });

  it('resumes idempotently after the op landed but before confirm (AC3)', () => {
    const state = scenarios['rekey-eligible']();
    const registry = buildRegistry(state);
    const did = (registry.list_identities({}) as string[])[0];

    registry.build_rekey_cmd({ did });
    registry.submit_rekey_cmd({ did }); // op lands: rotationKeys now 3, staging still set

    // Simulate an interruption before confirm: the identity reads as new-model, yet a re-key is
    // still in progress, so it stays eligible and build resumes rather than rejecting.
    const mid = registry.get_stored_did_doc({ did }) as Record<string, unknown>;
    expect((mid.rotationKeys as string[]).length).toBe(3);
    expect(isOldModelRecovery(did, mid)).toBe(false);
    expect(registry.rekey_in_progress_cmd({ did })).toBe(true);

    // Re-running build then submit converges on the SAME terminal state (no fourth key, same
    // recovery key at [1]).
    expect(() => registry.build_rekey_cmd({ did })).not.toThrow();
    registry.submit_rekey_cmd({ did });
    const after = registry.get_stored_did_doc({ did }) as Record<string, unknown>;
    const keys = after.rotationKeys as string[];
    expect(keys.length).toBe(3);
    expect(keys[1]).toBe(fakeRecoveryKeyId(did));

    registry.confirm_rekey_cmd({ did });
    expect(registry.rekey_in_progress_cmd({ did })).toBe(false);
  });

  it('rejects a re-key when the wallet device key is not the root key', () => {
    const state = scenarios['fresh-install']();
    state.pdsUrl = 'https://harness.pds.local';
    // An identity whose device key is NOT rotationKeys[0] (interop-style) is not additively
    // re-keyable by this wallet.
    const identity = seedIdentity({ handle: 'interop.harness.pds.local', deviceKeyIsRoot: false });
    state.identities.push(identity);
    const registry = buildRegistry(state);

    try {
      registry.build_rekey_cmd({ did: identity.did });
      throw new Error('build should have rejected a non-root device key');
    } catch (e) {
      expect((e as { code: string }).code).toBe('WALLET_NOT_AUTHORIZED');
    }
  });
});
