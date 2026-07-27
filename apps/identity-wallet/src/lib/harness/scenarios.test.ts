import { describe, it, expect } from 'vitest';
import {
  scenarios,
  buildScenario,
  isScenarioName,
  DEFAULT_SCENARIO,
  type ScenarioName,
} from './scenarios';
import { buildRegistry } from './registry';
import { deriveIdentityPanelState } from '../identity-status';
import { getDeadline, getUrgency, type Urgency } from '../deadline';

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

  // Each alert preset exists to reach ONE `UrgencyBadge` state, and the state is chosen
  // entirely by the seeded change's age against the live clock — so "an alert exists" is
  // the one assertion that stays green while the fixture silently ages into a different
  // band (which is exactly how `alert-active` came to render an expired window). Assert
  // the badge urgency each fixture is *supposed* to produce, measured the way
  // `AlertDetailScreen` measures it: `getUrgency(getDeadline(createdAt))`.
  const alertBands: ReadonlyArray<[ScenarioName, Urgency, Urgency]> = [
    // scenario, badge urgency (time left), panel urgency (any live alert is critical)
    ['alert-active', 'safe', 'critical'],
    ['alert-warning', 'warning', 'critical'],
    ['alert-critical', 'critical', 'critical'],
    ['alert-expired', 'expired', 'expired'],
  ];

  it.each(alertBands)('%s seeds a %s alert', (name, badgeUrgency, panelUrgency) => {
    const state = scenarios[name]();
    const alerts = state.identities[0].alerts;
    expect(alerts).toHaveLength(1);

    expect(getUrgency(getDeadline(alerts[0].createdAt))).toBe(badgeUrgency);
    expect(deriveIdentityPanelState(alerts, false).urgency).toBe(panelUrgency);
  });

  // The badge's `safe` and the panel's `safe` deliberately mean different things — "time
  // left" versus "all clear" — so an alarmed identity must never reach the panel's.
  it('no alert preset lets the panel report all-clear', () => {
    for (const [name] of alertBands) {
      const state = scenarios[name]();
      expect(deriveIdentityPanelState(state.identities[0].alerts, false).urgency).not.toBe('safe');
    }
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

  it('media backup flow: opt in, mirror everything, report a restore (AC2.1)', () => {
    const state = scenarios['one-identity']();
    const registry = buildRegistry(state);
    const did = state.identities[0].did;

    // Available but not opted in, nothing mirrored yet.
    const before = registry.get_blob_backup_status({ did }) as {
      enabled: boolean;
      location: string | null;
      backedUpCount: number;
    };
    expect(before.enabled).toBe(false);
    expect(before.location).toBe('icloud');
    expect(before.backedUpCount).toBe(0);

    registry.set_blob_backup_enabled({ did, enabled: true });
    const run = registry.run_blob_backup({ did }) as {
      listed: number;
      fetched: number;
      alreadyPresent: number;
      backedUpCount: number;
    };
    expect(run.fetched).toBe(run.listed);
    expect(run.backedUpCount).toBe(run.listed);

    // A second pass is incremental: everything already present.
    const second = registry.run_blob_backup({ did }) as { fetched: number; alreadyPresent: number };
    expect(second.fetched).toBe(0);
    expect(second.alreadyPresent).toBe(run.listed);

    const after = registry.get_blob_backup_status({ did }) as {
      enabled: boolean;
      backedUpCount: number;
      backedUpBytes: number;
      lastBackupAt: string | null;
    };
    expect(after.enabled).toBe(true);
    expect(after.backedUpCount).toBe(run.listed);
    expect(after.backedUpBytes).toBeGreaterThan(0);
    expect(after.lastBackupAt).not.toBeNull();

    // iOS has evicted one of the mirrored files to an iCloud placeholder; the restore
    // downloads it first, reports the count, and clears the eviction.
    const evicted = state.identities[0].blobBackup.mirroredCids[0];
    state.identities[0].blobBackup.evictedCids = [evicted];

    const restore = registry.restore_blob_backup({ did }) as {
      manifestCount: number;
      uploaded: number;
      downloadedFromIcloud: number;
    };
    expect(restore.uploaded).toBe(run.listed);
    expect(restore.manifestCount).toBe(run.listed);
    expect(restore.downloadedFromIcloud).toBe(1);
    expect(state.identities[0].blobBackup.evictedCids).toEqual([]);
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
