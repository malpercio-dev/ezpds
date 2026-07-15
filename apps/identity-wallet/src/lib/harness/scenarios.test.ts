import { describe, it, expect } from 'vitest';
import { scenarios, buildScenario, isScenarioName, DEFAULT_SCENARIO } from './scenarios';
import { buildRegistry } from './registry';

describe('wallet harness scenarios', () => {
  it('fresh-install has no identities and no PDS configured', () => {
    const state = scenarios['fresh-install']();
    expect(state.identities).toHaveLength(0);
    expect(state.pdsUrl).toBeNull();
  });

  it('one-identity seeds exactly one identity', () => {
    const state = scenarios['one-identity']();
    expect(state.identities).toHaveLength(1);
    expect(state.pdsUrl).not.toBeNull();
  });

  it('alert-active surfaces an unauthorized change', () => {
    const state = scenarios['alert-active']();
    expect(state.identities[0].alerts.length).toBeGreaterThan(0);
  });

  it('migration-in-flight parks a prepared migration', () => {
    const state = scenarios['migration-in-flight']();
    expect(state.migration).not.toBeNull();
    expect(state.migration?.sourceAuthenticated).toBe(true);
  });

  it('agent-connected binds a claimed agent', () => {
    const state = scenarios['agent-connected']();
    const registry = buildRegistry(state);
    const agents = registry.list_agents({}) as unknown[];
    expect(agents).toHaveLength(1);
  });

  it('buildScenario falls back to the default for an unknown name', () => {
    const fallback = buildScenario('does-not-exist');
    const expected = scenarios[DEFAULT_SCENARIO]();
    expect(fallback.identities.length).toBe(expected.identities.length);
  });

  it('isScenarioName narrows known names', () => {
    expect(isScenarioName('one-identity')).toBe(true);
    expect(isScenarioName('nope')).toBe(false);
  });

  it('create flow makes a new identity appear in list_identities (AC2.1)', () => {
    // Drive the create flow through the fake and assert statefulness end to end.
    const state = scenarios['fresh-install']();
    const registry = buildRegistry(state);
    registry.save_pds_url({ url: 'https://pds.example' });
    registry.create_account({ claimCode: 'CODE', email: 'a@b.co', handle: 'new.test' });
    const ceremony = registry.perform_did_ceremony({ handle: 'new.test', password: 'pw' }) as {
      did: string;
    };
    registry.register_handle({ handle: 'new.test' });
    registry.register_created_identity({ did: ceremony.did, handle: 'new.test' });
    const dids = registry.list_identities({}) as string[];
    expect(dids).toContain(ceremony.did);
  });

  it('claim flow persists the imported identity (AC2.1)', () => {
    const state = scenarios['fresh-install']();
    const registry = buildRegistry(state);
    const info = registry.resolve_identity({ handleOrDid: 'imported.test' }) as { did: string };
    registry.authenticate_source_pds({ did: info.did, identifier: 'imported.test', password: 'pw' });
    registry.submit_claim({ did: info.did });
    expect((registry.list_identities({}) as string[])).toContain(info.did);
  });
});
