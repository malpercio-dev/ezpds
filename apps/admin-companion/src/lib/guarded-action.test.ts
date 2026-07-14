import { describe, it, expect, vi, beforeEach } from 'vitest';

// Mirrors biometric.test.ts: the controller resolves `./biometric` and `./errors`
// statically, so both are re-mocked per test with vi.doMock + resetModules + a fresh
// dynamic import.
async function loadModule() {
  return await import('./guarded-action.svelte');
}

function mockBiometric(outcome: 'authenticated' | 'denied' | 'skipped' | 'unavailable') {
  vi.doMock('./biometric', () => ({
    requireUserPresence: vi.fn().mockResolvedValue(outcome),
    presenceAllows: (o: string) => o !== 'denied',
  }));
}

beforeEach(() => {
  vi.resetModules();
});

describe('createGuardedActions', () => {
  it('runs the action when the gate authenticates and clears busy afterward', async () => {
    mockBiometric('authenticated');
    const { createGuardedActions } = await loadModule();
    const g = createGuardedActions();
    const action = vi.fn().mockResolvedValue(undefined);

    await g.run({ id: 'x', reason: 'r', deniedHint: 'd', action });

    expect(action).toHaveBeenCalledOnce();
    expect(g.isBusy('x')).toBe(false);
    expect(g.errorFor('x')).toBeUndefined();
    expect(g.gateHint).toBeUndefined();
  });

  it('sets the gate hint and skips the action when the gate is denied', async () => {
    mockBiometric('denied');
    const { createGuardedActions } = await loadModule();
    const g = createGuardedActions();
    const action = vi.fn().mockResolvedValue(undefined);

    await g.run({ id: 'x', reason: 'r', deniedHint: 'confirm to revoke', action });

    expect(action).not.toHaveBeenCalled();
    expect(g.gateHint).toBe('confirm to revoke');
    expect(g.isBusy('x')).toBe(false);
  });

  it('classifies a thrown error into the per-id slot', async () => {
    mockBiometric('authenticated');
    const { createGuardedActions } = await loadModule();
    const g = createGuardedActions();

    await g.run({
      id: 'x',
      reason: 'r',
      deniedHint: 'd',
      action: vi.fn().mockRejectedValue({ code: 'UNREACHABLE' }),
    });

    expect(g.errorFor('x')?.chipLabel).toBe('unreachable');
    expect(g.isBusy('x')).toBe(false);
  });

  it('ignores a re-entrant call while the same id is busy', async () => {
    mockBiometric('authenticated');
    const { createGuardedActions } = await loadModule();
    const g = createGuardedActions();

    let release: () => void = () => {};
    const gate = new Promise<void>((r) => (release = r));
    const action = vi.fn().mockImplementation(() => gate);

    const first = g.run({ id: 'x', reason: 'r', deniedHint: 'd', action });
    expect(g.isBusy('x')).toBe(true);
    // A second tap while busy is a no-op.
    await g.run({ id: 'x', reason: 'r', deniedHint: 'd', action });
    expect(action).toHaveBeenCalledOnce();

    release();
    await first;
    expect(g.isBusy('x')).toBe(false);
  });

  it('clears a prior error at the start of the next run', async () => {
    mockBiometric('authenticated');
    const { createGuardedActions } = await loadModule();
    const g = createGuardedActions();

    await g.run({ id: 'x', reason: 'r', deniedHint: 'd', action: vi.fn().mockRejectedValue({ code: 'UNREACHABLE' }) });
    expect(g.errorFor('x')).toBeDefined();

    await g.run({ id: 'x', reason: 'r', deniedHint: 'd', action: vi.fn().mockResolvedValue(undefined) });
    expect(g.errorFor('x')).toBeUndefined();
  });
});
