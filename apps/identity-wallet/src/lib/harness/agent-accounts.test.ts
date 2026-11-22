import { describe, it, expect } from 'vitest';
import { buildRegistry } from './registry';
import { buildScenario } from './scenarios';
import { HARNESS_AGENT_SCOPES } from './state';
import type {
  AgentClaimPreview,
  AgentList,
  WidenedScopes,
  ChildAssertion,
  ChildDeletion,
  ChildReconciliation,
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

/**
 * The recovery epilogue as My Agents drives it: a restored device gets a verdict per child, the
 * device that minted them gets silence, and "we cannot derive this key" never blurs into "we
 * could not ask".
 */
describe('recovery epilogue for children', () => {
  it('reports nothing on the device that minted the children', () => {
    const state = buildScenario('agent-children');
    const registry = buildRegistry(state);
    const did = state.identities[0].did;

    const result = registry.reconcile_children({ did }) as ChildReconciliation;

    expect(result.rebuilt).toBe(false);
    expect(result.children).toEqual([]);
  });

  it('gives a restored device a verdict per child and rebuilds the counter', () => {
    const state = buildScenario('agent-children-recovered');
    const registry = buildRegistry(state);
    const did = state.identities[0].did;

    const result = registry.reconcile_children({ did }) as ChildReconciliation;

    expect(result.rebuilt).toBe(true);
    expect(result.children.map((c) => c.status)).toEqual(['matched', 'unmatched', 'unchecked']);
    // Only a match proves an index is spent, so the counter clears the highest matched one.
    expect(result.nextIndex).toBe(1);
  });

  it('keeps a key it cannot derive distinct from one it could not check', () => {
    const state = buildScenario('agent-children-recovered');
    const registry = buildRegistry(state);
    const did = state.identities[0].did;

    const result = registry.reconcile_children({ did }) as ChildReconciliation;
    const unmatched = result.children.find((c) => c.status === 'unmatched');
    const unchecked = result.children.find((c) => c.status === 'unchecked');

    expect(unmatched?.handle).toBe('archivist.harness.pds.local');
    expect(unchecked?.handle).toBe('courier.harness.pds.local');
    // The unreadable one carries a reason; the unrecoverable one is a finding, not an error.
    expect(unchecked && 'message' in unchecked).toBe(true);
    expect(unmatched && 'message' in unmatched).toBe(false);
  });

  it('keeps reporting a child it still cannot derive, run after run', () => {
    const state = buildScenario('agent-children-recovered');
    const registry = buildRegistry(state);
    const did = state.identities[0].did;

    registry.reconcile_children({ did });
    const again = registry.reconcile_children({ did }) as ChildReconciliation;

    // Only a match advances the counter, so it can never clear a list holding a child this seed
    // does not derive — and an unrecoverable account keeps saying so instead of being marked read.
    expect(again.rebuilt).toBe(true);
    expect(again.children.map((c) => c.status)).toEqual(['matched', 'unmatched', 'unchecked']);
  });

  it('refuses an identity with no delegation seed', () => {
    const state = buildScenario('agent-accounts-unprovisioned');
    const registry = buildRegistry(state);
    const did = state.identities[0].did;
    expect(() => registry.reconcile_children({ did })).toThrow();
  });
});

/**
 * Owner-gated scope widening as the detail screens drive it (ADR-0041): the operator's profile
 * offers more than the grant, the owner approves the shown set, and the grant only grows.
 */
describe('agent scope widening', () => {
  it('offers the scopes the raised profile adds, then grows the grant to hold them', () => {
    const state = buildScenario('agent-scopes-available');
    const registry = buildRegistry(state);
    const did = state.identities[0].did;

    const before = registry.list_agents({ did }) as AgentList;
    const agent = before.agents[0];
    expect(before.scopeProfile).toContain('account:email');
    expect(agent.scopes).not.toContain('account:email');

    const widened = registry.widen_agent_scopes({
      did,
      registrationId: agent.registrationId,
      scopes: before.scopeProfile,
    }) as WidenedScopes;
    expect(widened.effectiveScopes).toEqual([...before.scopeProfile].sort());

    const after = registry.list_agents({ did }) as AgentList;
    expect(after.agents[0].scopes).toEqual(widened.scopes);
    const audit = registry.get_agent_audit({ did, registrationId: agent.registrationId }) as {
      events: { eventType: string }[];
    };
    expect(audit.events.some((e) => e.eventType === 'scopes_widened')).toBe(true);
  });

  it('keeps a suspended scope stored, and never stores a shown scope outside the profile', () => {
    const state = buildScenario('agent-scopes-suspended');
    const registry = buildRegistry(state);
    const did = state.identities[0].did;
    const { agents, scopeProfile } = registry.list_agents({ did }) as AgentList;
    const agent = agents[0];
    expect(agent.scopes).toContain('repo:*?action=delete');
    expect(agent.effectiveScopes).not.toContain('repo:*?action=delete');

    const widened = registry.widen_agent_scopes({
      did,
      registrationId: agent.registrationId,
      scopes: [...scopeProfile, 'identity:*'],
    }) as WidenedScopes;
    expect(widened.scopes).toContain('repo:*?action=delete');
    expect(widened.scopes).not.toContain('identity:*');
    expect(widened.effectiveScopes).not.toContain('repo:*?action=delete');
  });

  it('widens a live child, which the follow-up renewal then carries', () => {
    const state = buildScenario('agent-scopes-available');
    const registry = buildRegistry(state);
    const did = state.identities[0].did;
    const { scopeProfile } = registry.list_agents({ did }) as AgentList;
    const child = (registry.list_children({ did }) as ChildSummary[])[0];

    registry.widen_agent_scopes({ did, registrationId: child.registrationId, scopes: scopeProfile });
    const renewed = registry.remint_child_assertion({ did, childDid: child.did }) as ChildAssertion;
    expect(renewed.scopes).toContain('account:email');
  });

  it('refuses an agent that is not live, and an unknown one', () => {
    const state = buildScenario('agent-children');
    const registry = buildRegistry(state);
    const did = state.identities[0].did;
    const revoked = (registry.list_children({ did }) as ChildSummary[]).find(
      (c) => c.status === 'revoked'
    )!;
    expect(() =>
      registry.widen_agent_scopes({ did, registrationId: revoked.registrationId, scopes: [] })
    ).toThrow(expect.objectContaining({ code: 'ACCESS_DENIED' }));
    expect(() =>
      registry.widen_agent_scopes({ did, registrationId: 'reg-nobody', scopes: [] })
    ).toThrow(expect.objectContaining({ code: 'AGENT_NOT_FOUND' }));
  });
});
