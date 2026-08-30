import { describe, it, expect } from 'vitest';
import { buildRegistry } from './registry';
import { buildScenario } from './scenarios';
import type { AgentClaimPreview, CollectedShare, MintedChild } from '$lib/ipc';

/**
 * The delegation-seed gate as the screens see it: an identity created before agent
 * accounts existed reports unprovisioned, and the share-verification ceremony — the
 * same one recovery runs, minus the anchor — is what flips it.
 */
describe('agent-accounts provisioning gate', () => {
  it('reports a seeded identity as provisioned', () => {
    const state = buildScenario('one-identity');
    const registry = buildRegistry(state);
    const did = state.identities[0].did;
    expect(registry.agent_accounts_provisioned({ did })).toBe(true);
  });

  it('reports an unknown did as unprovisioned rather than throwing', () => {
    const registry = buildRegistry(buildScenario('one-identity'));
    expect(registry.agent_accounts_provisioned({ did: 'did:plc:nobody' })).toBe(false);
  });

  it('flips to provisioned once two shares verify', () => {
    const state = buildScenario('agent-accounts-unprovisioned');
    const registry = buildRegistry(state);
    const did = state.identities[0].did;

    expect(registry.agent_accounts_provisioned({ did })).toBe(false);

    // Exactly what EnableAgentAccountsScreen drives: start against the DID, take the
    // escrow share, verify. No `recover_identity` — provisioning rotates nothing.
    registry.start_share_recovery({ identifier: did });
    registry.initiate_escrow_release({});
    const released = registry.request_escrow_release({ otp: '000000' }) as {
      status: string;
      share: CollectedShare | null;
    };
    expect(released.status).toBe('released');
    registry.verify_recovery_shares({});

    expect(registry.agent_accounts_provisioned({ did })).toBe(true);
  });
});

/**
 * The cooperative mint as the approval screen drives it: an anonymous registration proposes a
 * handle, the user settles it, and the identity ends up owning an account it did not own before.
 */
describe('cooperative child mint', () => {
  it('previews an anonymous registration carrying the agent’s proposed handle', () => {
    const registry = buildRegistry(buildScenario('agent-child-mint'));
    const preview = registry.preview_agent_claim({ userCode: 'CHILD1' }) as AgentClaimPreview;

    expect(preview.registrationType).toBe('anonymous');
    expect(preview.handleHint).toBe('scribe.harness.pds.local');
    // The plain arm is unchanged — the fork is reachable only for an anonymous registration.
    const plain = registry.preview_agent_claim({ userCode: '4QX9TX' }) as AgentClaimPreview;
    expect(plain.registrationType).toBe('service_auth');
    expect(plain.handleHint).toBeUndefined();
  });

  it('mints a child with the handle the user settled on', () => {
    const state = buildScenario('agent-child-mint');
    const registry = buildRegistry(state);
    const did = state.identities[0].did;

    const child = registry.mint_child_from_claim({
      did,
      userCode: 'CHILD1',
      handle: 'archivist.harness.pds.local',
    }) as MintedChild;

    expect(child.handle).toBe('archivist.harness.pds.local');
    expect(child.did).not.toBe(did);
    expect(state.identities[0].children.map((c) => c.handle)).toContain(
      'archivist.harness.pds.local'
    );
  });

  it('gives each child its own DID', () => {
    const state = buildScenario('agent-child-mint');
    const registry = buildRegistry(state);
    const did = state.identities[0].did;

    const first = registry.mint_child_from_claim({ did, userCode: 'C1', handle: 'a.harness.pds.local' }) as MintedChild;
    const second = registry.mint_child_from_claim({ did, userCode: 'C2', handle: 'b.harness.pds.local' }) as MintedChild;

    expect(first.did).not.toBe(second.did);
  });

  it('refuses a taken handle without minting anything', () => {
    const state = buildScenario('agent-child-mint');
    const registry = buildRegistry(state);
    const did = state.identities[0].did;
    const before = state.identities[0].children.length;

    // The agent's own proposal collides — the hint is never a commitment.
    expect(() =>
      registry.mint_child_from_claim({ did, userCode: 'CHILD1', handle: 'scribe.harness.pds.local' })
    ).toThrow(expect.objectContaining({ code: 'HANDLE_REJECTED' }));
    // ...and so does the parent's own handle.
    expect(() =>
      registry.mint_child_from_claim({ did, userCode: 'CHILD1', handle: state.identities[0].handle })
    ).toThrow(expect.objectContaining({ code: 'HANDLE_REJECTED' }));

    expect(state.identities[0].children.length).toBe(before);
  });

  it('refuses to mint at all for an unprovisioned identity', () => {
    const state = buildScenario('agent-accounts-unprovisioned');
    const registry = buildRegistry(state);
    const did = state.identities[0].did;

    expect(() =>
      registry.mint_child_from_claim({ did, userCode: 'CHILD1', handle: 'scribe.harness.pds.local' })
    ).toThrow(expect.objectContaining({ code: 'NOT_PROVISIONED' }));
    expect(state.identities[0].children).toEqual([]);
  });
});
