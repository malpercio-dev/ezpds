import { describe, it, expect } from 'vitest';
import { buildRegistry } from './registry';
import { scenarios } from './scenarios';
import { fakeRecoveryKeyId } from './state';
import type { SelfHeldKitPreview, SelfHeldKitResult } from '$lib/ipc';

/**
 * Drives the MM-456 escrow-less self-held kit through the fake end to end, mirroring the ACs:
 *  - a foreign-hosted root-key identity installs a recovery key at rotationKeys[1] with the
 *    claimed tail shifted down intact (AC1);
 *  - the ceremony hands the user BOTH Shares 2 and 3, and the staging slot survives until an
 *    explicit confirmation (AC2);
 *  - the flow steps aside on an escrow-capable host, leaving `rekey.rs`'s path untouched (AC4).
 */
describe('wallet harness self-held Shamir kit (MM-456)', () => {
  it('installs the recovery key at [1] and shifts the claimed tail down intact (AC1)', () => {
    const state = scenarios['self-held-kit']();
    const registry = buildRegistry(state);
    const did = (registry.list_identities({}) as string[])[0];

    const before = registry.get_stored_did_doc({ did }) as Record<string, unknown>;
    const keysBefore = before.rotationKeys as string[];
    expect(keysBefore.length, 'a claimed identity carries an arbitrary tail').toBe(3);
    expect(registry.self_held_kit_in_progress_cmd({ did })).toBe(false);

    const preview = registry.build_self_held_kit_cmd({ did }) as SelfHeldKitPreview;
    expect(preview.diff.addedKeys).toEqual([fakeRecoveryKeyId(did)]);
    expect(preview.diff.removedKeys, 'the kit removes nothing').toEqual([]);
    expect(preview.pdsUrl).toBe('https://bsky.social');
    expect(registry.self_held_kit_in_progress_cmd({ did })).toBe(true);

    registry.submit_self_held_kit_cmd({ did }) as SelfHeldKitResult;

    const after = registry.get_stored_did_doc({ did }) as Record<string, unknown>;
    expect(after.rotationKeys).toEqual([
      keysBefore[0],
      fakeRecoveryKeyId(did),
      keysBefore[1],
      keysBefore[2],
    ]);
  });

  it('hands the user two distinct shares and holds staging until confirmation (AC2)', () => {
    const state = scenarios['self-held-kit']();
    const registry = buildRegistry(state);
    const did = (registry.list_identities({}) as string[])[0];

    registry.build_self_held_kit_cmd({ did });
    const result = registry.submit_self_held_kit_cmd({ did }) as SelfHeldKitResult;

    // Both shares are the user's, and they are genuinely different material — a screen that
    // rendered one share twice would leave the user one share short of the threshold.
    expect(result.share2).not.toBe(result.share3);
    expect(result.share2Words).not.toBe(result.share3Words);
    expect(result.share2Words.split(' ').length).toBe(42);
    expect(result.share3Words.split(' ').length).toBe(42);

    // The staging slot survives the submit — it is the last local home of Shares 2 and 3 until
    // the user says they have saved them.
    expect(registry.self_held_kit_in_progress_cmd({ did })).toBe(true);
    registry.confirm_self_held_kit_cmd({ did });
    expect(registry.self_held_kit_in_progress_cmd({ did })).toBe(false);
  });

  it('converges on the same terminal state when interrupted and resumed', () => {
    const state = scenarios['self-held-kit']();
    const registry = buildRegistry(state);
    const did = (registry.list_identities({}) as string[])[0];

    registry.build_self_held_kit_cmd({ did });
    registry.submit_self_held_kit_cmd({ did });
    const afterFirst = registry.get_stored_did_doc({ did }) as Record<string, unknown>;

    // An app kill between submit and confirm: build + submit run again against an identity
    // whose op already landed. Neither may regenerate the set or double-insert the key.
    const resumedPreview = registry.build_self_held_kit_cmd({ did }) as SelfHeldKitPreview;
    expect(resumedPreview.recoveryKeyId).toBe(fakeRecoveryKeyId(did));
    registry.submit_self_held_kit_cmd({ did });

    const afterResume = registry.get_stored_did_doc({ did }) as Record<string, unknown>;
    expect(afterResume.rotationKeys).toEqual(afterFirst.rotationKeys);
  });

  it('steps aside on an escrow-capable host, leaving the re-key path to serve it (AC4)', () => {
    const state = scenarios['self-held-kit']();
    state.pdsCapabilities = { version: '0.8.5', reached: true, capabilities: ['escrow'] };
    const registry = buildRegistry(state);
    const did = (registry.list_identities({}) as string[])[0];

    expect(() => registry.build_self_held_kit_cmd({ did })).toThrow(
      expect.objectContaining({ code: 'HOST_OFFERS_ESCROW' })
    );
  });

  it('refuses an identity whose root rotation key is not this wallet', () => {
    const state = scenarios['self-held-kit']();
    state.identities[0].rotationKeys = [
      'did:key:zharnessForeignPdsKey',
      state.identities[0].deviceKeyId,
    ];
    const registry = buildRegistry(state);
    const did = state.identities[0].did;

    expect(() => registry.build_self_held_kit_cmd({ did })).toThrow(
      expect.objectContaining({ code: 'WALLET_NOT_AUTHORIZED' })
    );
  });
});
