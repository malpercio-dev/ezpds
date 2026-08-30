import { describe, it, expect } from 'vitest';
import { buildRegistry } from './registry';
import { buildScenario } from './scenarios';
import type { CollectedShare } from '$lib/ipc';

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
