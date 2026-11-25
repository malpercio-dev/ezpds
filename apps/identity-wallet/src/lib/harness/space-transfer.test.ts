import { describe, it, expect } from 'vitest';
import { buildRegistry } from './registry';
import { scenarios } from './scenarios';
import type { MigrationError } from '$lib/ipc';

/**
 * The space transfer through the fake, driven in the order `MigrationProgressScreen` runs the
 * legs, for each spaces scenario: the clean move, the destination without spaces, and the
 * space blob that can't be served.
 */
function startMove(name: 'migration-spaces' | 'migration-spaces-unsupported' | 'migration-space-blob-loss') {
  const state = scenarios[name]();
  const registry = buildRegistry(state);
  const did = state.identities[0].did;
  registry.prepare_migration({ did, destPdsUrl: 'https://destination.harness.pds.local' });
  registry.authenticate_migration_source({ did });
  registry.create_destination_account({ did });
  registry.transfer_repo({ did });
  registry.transfer_blobs({ did, acceptLoss: false });
  return { state, registry, did };
}

function rejection(fn: () => unknown): MigrationError {
  try {
    fn();
  } catch (raw) {
    return raw as MigrationError;
  }
  throw new Error('expected a rejection');
}

describe('wallet harness: space transfer', () => {
  it('migration-spaces moves an authority space and a writer space, then verifies', () => {
    const { state, registry, did } = startMove('migration-spaces');
    const [authority, writer] = state.spaceTransfer.sourceSpaces;
    expect(authority.startsWith(`at://${did}/`)).toBe(true);
    expect(writer.startsWith(`at://${did}/`)).toBe(false);

    registry.transfer_spaces({ did, acceptLoss: false });
    expect(state.migration?.spacesTransferred).toBe(true);
    registry.transfer_preferences({ did });
    registry.verify_import({ did });
    expect(state.migration?.verified).toBe(true);
  });

  it('migration-spaces-unsupported stops before anything moves until the loss is accepted', () => {
    const { state, registry, did } = startMove('migration-spaces-unsupported');

    const err = rejection(() => registry.transfer_spaces({ did, acceptLoss: false }));
    expect(err.code).toBe('SPACES_UNSUPPORTED');
    if (err.code !== 'SPACES_UNSUPPORTED') return;
    expect(err.spaces).toEqual(state.spaceTransfer.sourceSpaces);
    expect(state.migration?.spacesTransferred).toBe(false);

    registry.transfer_spaces({ did, acceptLoss: true });
    expect(state.migration?.spacesTransferred).toBe(true);
  });

  it('migration-space-blob-loss names the space on the manifest entry', () => {
    const { state, registry, did } = startMove('migration-space-blob-loss');

    const err = rejection(() => registry.transfer_spaces({ did, acceptLoss: false }));
    expect(err.code).toBe('BLOB_DRAIN_INCOMPLETE');
    if (err.code !== 'BLOB_DRAIN_INCOMPLETE') return;
    expect(err.losses).toHaveLength(1);
    expect(err.losses[0].space).toBe(state.spaceTransfer.sourceSpaces[0]);

    registry.transfer_spaces({ did, acceptLoss: true });
    expect(state.migration?.spacesTransferred).toBe(true);
  });

  it('a recovery session advances with no spaces to restore', () => {
    const state = scenarios['migration-spaces-unsupported']();
    const registry = buildRegistry(state);
    const did = state.identities[0].did;
    registry.prepare_disaster_recovery({ did });
    registry.transfer_spaces({ did });
    expect(state.migration?.spacesTransferred).toBe(true);
  });
});
