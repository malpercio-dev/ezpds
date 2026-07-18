import { describe, it, expect } from 'vitest';
import { buildRegistry, type Registry } from './registry';
import { buildScenario } from './scenarios';
import type {
  CollectedShare,
  EscrowReleaseStatus,
  EpilogueResult,
  PendingEpilogue,
  RecoveryTarget,
  RecoveredIdentity,
} from '$lib/ipc';

/**
 * Drives the recovery fake exactly as the screens do, across the named
 * scenarios, so every advertised `window.__harness` recovery state is proven
 * reachable (and stays reachable) by `pnpm test`.
 */

function setup(scenario: string): { registry: Registry; state: ReturnType<typeof buildScenario> } {
  const state = buildScenario(scenario);
  return { registry: buildRegistry(state), state };
}

function start(registry: Registry): RecoveryTarget {
  return registry.start_share_recovery({ identifier: 'alice.harness.pds.local' }) as RecoveryTarget;
}

function code(raw: unknown): string {
  return (raw as { code: string }).code;
}

function expectThrowCode(fn: () => unknown, expected: string): unknown {
  try {
    fn();
  } catch (raw) {
    expect(code(raw)).toBe(expected);
    return raw;
  }
  throw new Error(`expected ${expected} to be thrown`);
}

describe('recovery flow scenarios', () => {
  it('recover-escrow: happy path A — iCloud share + immediate escrow release', () => {
    const { state, registry } = setup('recover-escrow');
    const target = start(registry);
    expect(target.share1Loaded).toBe(true);
    expect(target.collected).toHaveLength(1);

    registry.initiate_escrow_release({});
    const status = registry.request_escrow_release({ otp: '123456' }) as EscrowReleaseStatus;
    expect(status.status).toBe('released');
    expect(status.share?.index).toBe(2);

    const verified = registry.verify_recovery_shares({}) as RecoveredIdentity;
    expect(verified.did).toBe(target.did);
    expect(verified.rotationKeys).toContain(verified.recoveryKeyId);

    registry.recover_identity({});
    expect(state.identities.map((i) => i.did)).toContain(target.did);

    const result = registry.run_recovery_epilogue({ skipEscrow: false }) as EpilogueResult;
    expect(result.escrowDeposited).toBe(true);
    expect(result.share3Words.split(' ').length).toBe(42);

    registry.confirm_recovery_backup({});
    expect(registry.get_pending_recovery_epilogue({})).toBeNull();
  });

  it('recover-sovereign: happy path B — iCloud share + manually entered Share 3', () => {
    const { state, registry } = setup('recover-sovereign');
    const target = start(registry);
    expect(target.share1Loaded).toBe(true);

    const share = registry.add_recovery_share({
      share: state.recovery.fixtures.share3Words,
    }) as CollectedShare;
    expect(share.index).toBe(3);

    const verified = registry.verify_recovery_shares({}) as RecoveredIdentity;
    expect(verified.did).toBe(target.did);

    registry.recover_identity({});
    const result = registry.run_recovery_epilogue({ skipEscrow: true }) as EpilogueResult;
    expect(result.escrowSkipped).toBe(true);
    expect(result.escrowDeposited).toBe(false);
  });

  it('recover-wrong-set: a cross-generation share names both set_ids', () => {
    const { state, registry } = setup('recover-wrong-set');
    start(registry);
    const raw = expectThrowCode(
      () => registry.add_recovery_share({ share: state.recovery.fixtures.wrongSet }),
      'SHARE_SET_MISMATCH'
    ) as { expectedSetId: number; gotSetId: number };
    expect(raw.expectedSetId).not.toBe(raw.gotSetId);
  });

  it('recover-corrupt-share: a damaged share is a checksum failure, not a format one', () => {
    const { state, registry } = setup('recover-corrupt-share');
    start(registry);
    expectThrowCode(
      () => registry.add_recovery_share({ share: state.recovery.fixtures.corrupt }),
      'SHARE_CHECKSUM'
    );
    expectThrowCode(() => registry.add_recovery_share({ share: 'garbage' }), 'SHARE_FORMAT');
  });

  it('recover-mismatch: valid shares for the wrong identity fail verification', () => {
    const { state, registry } = setup('recover-mismatch');
    start(registry);
    registry.add_recovery_share({ share: state.recovery.fixtures.share3 });
    expectThrowCode(
      () => registry.verify_recovery_shares({}),
      'SHARES_DO_NOT_MATCH_IDENTITY'
    );
  });

  it('recover-pending-delay: the OTP opens a window; a later poll releases', () => {
    const { registry } = setup('recover-pending-delay');
    start(registry);
    registry.initiate_escrow_release({});

    const opened = registry.request_escrow_release({ otp: '123456' }) as EscrowReleaseStatus;
    expect(opened.status).toBe('pending');
    expect(opened.availableAt).not.toBeNull();

    const still = registry.request_escrow_release({}) as EscrowReleaseStatus;
    expect(still.status).toBe('pending');

    const released = registry.request_escrow_release({}) as EscrowReleaseStatus;
    expect(released.status).toBe('released');
    expect(released.share?.index).toBe(2);
  });

  it('recover-cancelled: polls after a cancelled release answer the uniform 401', () => {
    const { registry } = setup('recover-cancelled');
    start(registry);
    registry.initiate_escrow_release({});
    const opened = registry.request_escrow_release({ otp: '123456' }) as EscrowReleaseStatus;
    expect(opened.status).toBe('pending');
    expectThrowCode(() => registry.request_escrow_release({}), 'RELEASE_UNAUTHORIZED');
  });

  it('a wrong OTP answers the uniform 401 without opening a window', () => {
    const { registry } = setup('recover-escrow');
    start(registry);
    expectThrowCode(
      () => registry.request_escrow_release({ otp: 'wrong' }),
      'RELEASE_UNAUTHORIZED'
    );
    expectThrowCode(() => registry.request_escrow_release({}), 'RELEASE_UNAUTHORIZED');
  });

  it('recover-epilogue-resume: launch finds the pending epilogue and resumes it', () => {
    const { registry } = setup('recover-epilogue-resume');
    const pending = registry.get_pending_recovery_epilogue({}) as PendingEpilogue;
    expect(pending).not.toBeNull();
    expect(pending.opSubmitted).toBe(true);
    expect(pending.share1Written).toBe(false);

    const result = registry.run_recovery_epilogue({ skipEscrow: false }) as EpilogueResult;
    expect(result.escrowDeposited).toBe(true);

    registry.confirm_recovery_backup({});
    expect(registry.get_pending_recovery_epilogue({})).toBeNull();
  });

  it('an injected escrow failure keeps durable progress and resumes cleanly', () => {
    const { state, registry } = setup('recover-sovereign');
    start(registry);
    registry.add_recovery_share({ share: state.recovery.fixtures.share3 });
    registry.verify_recovery_shares({});
    registry.recover_identity({});

    state.recovery.failEpilogueEscrowOnce = true;
    expectThrowCode(
      () => registry.run_recovery_epilogue({ skipEscrow: false }),
      'ESCROW_DEPOSIT_FAILED'
    );
    const pending = registry.get_pending_recovery_epilogue({}) as PendingEpilogue;
    expect(pending.opSubmitted).toBe(true);

    const result = registry.run_recovery_epilogue({ skipEscrow: false }) as EpilogueResult;
    expect(result.escrowDeposited).toBe(true);
  });

  it('duplicate and post-release re-entry behave idempotently', () => {
    const { state, registry } = setup('recover-escrow');
    start(registry);
    registry.add_recovery_share({ share: state.recovery.fixtures.share3 });
    expectThrowCode(
      () => registry.add_recovery_share({ share: state.recovery.fixtures.share3 }),
      'DUPLICATE_SHARE'
    );
    const removed = registry.remove_recovery_share({ index: 3 }) as CollectedShare[];
    expect(removed.some((s) => s.index === 3)).toBe(false);
  });
});
