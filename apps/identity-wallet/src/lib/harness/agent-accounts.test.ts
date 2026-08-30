import { describe, it, expect } from 'vitest';
import { buildRegistry } from './registry';
import { buildScenario } from './scenarios';
import { HARNESS_AGENT_SCOPES } from './state';
import type {
  AgentClaimPreview,
  ChildAssertion,
  ChildDeletion,
  ChildSummary,
  CollectedShare,
  MintedChild,
} from '$lib/ipc';

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

/**
 * The parent console — what My Agents and the child detail screen drive. The states these cover
 * are the ones a screen cannot distinguish on its own: deleting revokes as a side effect, so
 * `status` alone never separates a retired child from a merely revoked one.
 */
describe('child lifecycle', () => {
  const setup = () => {
    const state = buildScenario('agent-children');
    return { state, registry: buildRegistry(state), did: state.identities[0].did };
  };

  it('lists a parent’s children with scopes and every lifecycle state', () => {
    const { registry, did } = setup();
    const children = registry.list_children({ did }) as ChildSummary[];

    expect(children.map((c) => c.handle)).toEqual([
      'scribe.harness.pds.local',
      'archivist.harness.pds.local',
      'retired.harness.pds.local',
    ]);
    // AC4.1: the detail screen renders the grant, so the list has to carry it.
    expect(children[0].scopes).toEqual(HARNESS_AGENT_SCOPES);
    expect(children[0].deleteAfter).toBeUndefined();
    // The retired child is `revoked` like the middle one — only the purge date tells them apart.
    expect(children[1].status).toBe('revoked');
    expect(children[2].status).toBe('revoked');
    expect(children[2].deleteAfter).toBeTruthy();
  });

  it('does not list another identity’s children', () => {
    const { registry } = setup();
    expect(registry.list_children({ did: 'did:plc:nobody' })).toEqual([]);
  });

  it('revoke flips the child to revoked without scheduling a purge', () => {
    const { state, registry, did } = setup();
    const childDid = state.identities[0].children[0].did;

    registry.revoke_child({ did, childDid });

    const child = (registry.list_children({ did }) as ChildSummary[])[0];
    expect(child.status).toBe('revoked');
    // AC4.2 vs AC4.3: revoking keeps the account. Nothing is scheduled for removal.
    expect(child.deleteAfter).toBeUndefined();
  });

  it('delete revokes and schedules the purge in one call', () => {
    const { state, registry, did } = setup();
    const childDid = state.identities[0].children[0].did;

    const scheduled = registry.delete_child({ did, childDid }) as ChildDeletion;
    expect(scheduled.status).toBe('deletion_scheduled');
    expect(Date.parse(scheduled.deleteAfter)).toBeGreaterThan(Date.now());

    const child = (registry.list_children({ did }) as ChildSummary[])[0];
    // Delete implies revoke on the server; a screen that modelled them as independent would look
    // right against a fake that did too, and be wrong in production.
    expect(child.status).toBe('revoked');
    expect(child.deleteAfter).toBe(scheduled.deleteAfter);
  });

  it('renews a live child’s credential', () => {
    const { state, registry, did } = setup();
    const childDid = state.identities[0].children[0].did;

    const renewed = registry.remint_child_assertion({ did, childDid }) as ChildAssertion;
    expect(renewed.did).toBe(childDid);
    expect(renewed.identityAssertion).toBeTruthy();
    expect(Date.parse(renewed.assertionExpires)).toBeGreaterThan(Date.now());
  });

  it('refuses to renew a revoked child', () => {
    const { state, registry, did } = setup();
    // Revocation is one-way: renewal must never be a way back up the custody ladder.
    const childDid = state.identities[0].children[1].did;

    expect(() => registry.remint_child_assertion({ did, childDid })).toThrow(
      expect.objectContaining({ code: 'ACCESS_DENIED' })
    );
  });

  it('answers a uniform not-found for a child belonging to someone else', () => {
    const { state, registry } = setup();
    const childDid = state.identities[0].children[0].did;

    // Right child, wrong parent — the real routes reach children only via the parent, and never
    // confirm that a foreign child exists.
    for (const call of ['revoke_child', 'delete_child', 'remint_child_assertion'] as const) {
      expect(() => registry[call]({ did: 'did:plc:nobody', childDid })).toThrow(
        expect.objectContaining({ code: 'AGENT_NOT_FOUND' })
      );
    }
  });
});
