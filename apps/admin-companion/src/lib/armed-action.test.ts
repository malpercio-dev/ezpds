import { describe, it, expect, vi, beforeEach } from 'vitest';

async function loadModule() {
  return await import('./armed-action.svelte');
}

function mockBiometric(outcome: 'authenticated' | 'denied') {
  vi.doMock('./biometric', () => ({
    requireUserPresence: vi.fn().mockResolvedValue(outcome),
    presenceAllows: (o: string) => o !== 'denied',
  }));
}

const ok = {
  reason: 'Take down an account',
  deniedHint: 'confirm to take down',
  precondition: () => true,
};

beforeEach(() => {
  vi.resetModules();
});

describe('createArmedAction', () => {
  it('arms and disarms', async () => {
    mockBiometric('authenticated');
    const { createArmedAction } = await loadModule();
    const a = createArmedAction();
    expect(a.armed).toBe(false);
    a.arm();
    expect(a.armed).toBe(true);
    a.disarm();
    expect(a.armed).toBe(false);
  });

  it('runs the write and disarms on a confirmed gate', async () => {
    mockBiometric('authenticated');
    const { createArmedAction } = await loadModule();
    const a = createArmedAction();
    a.arm();
    const run = vi.fn().mockResolvedValue(undefined);

    await a.confirm({ ...ok, run });

    expect(run).toHaveBeenCalledOnce();
    expect(a.armed).toBe(false);
    expect(a.writing).toBe(false);
    expect(a.error).toBeUndefined();
  });

  it('sets the gate hint and stays armed when the gate is denied', async () => {
    mockBiometric('denied');
    const { createArmedAction } = await loadModule();
    const a = createArmedAction();
    a.arm();
    const run = vi.fn().mockResolvedValue(undefined);

    await a.confirm({ ...ok, run });

    expect(run).not.toHaveBeenCalled();
    expect(a.gateHint).toBe('confirm to take down');
    expect(a.armed).toBe(true);
  });

  it('classifies a thrown write into the error slot', async () => {
    mockBiometric('authenticated');
    const { createArmedAction } = await loadModule();
    const a = createArmedAction();
    a.arm();

    await a.confirm({ ...ok, run: vi.fn().mockRejectedValue({ code: 'UNREACHABLE' }) });

    expect(a.error?.chipLabel).toBe('unreachable');
    expect(a.armed).toBe(true); // a failed write leaves it armed for retry
  });

  it('does nothing when the precondition is false', async () => {
    mockBiometric('authenticated');
    const { createArmedAction } = await loadModule();
    const a = createArmedAction();
    const run = vi.fn().mockResolvedValue(undefined);

    await a.confirm({ ...ok, precondition: () => false, run });

    expect(run).not.toHaveBeenCalled();
  });

  it('suppresses the outcome when commit() is false (stale lookup)', async () => {
    mockBiometric('authenticated');
    const { createArmedAction } = await loadModule();
    const a = createArmedAction();
    a.arm();

    await a.confirm({ ...ok, run: vi.fn().mockResolvedValue(undefined), commit: () => false });
    // Write ran, but the result must not land: stays armed, no error.
    expect(a.armed).toBe(true);
    expect(a.error).toBeUndefined();

    await a.confirm({ ...ok, run: vi.fn().mockRejectedValue({ code: 'UNREACHABLE' }), commit: () => false });
    expect(a.error).toBeUndefined();
  });

  it('ignores a re-entrant confirm while writing', async () => {
    mockBiometric('authenticated');
    const { createArmedAction } = await loadModule();
    const a = createArmedAction();
    a.arm();

    let release: () => void = () => {};
    const gate = new Promise<void>((r) => (release = r));
    const run = vi.fn().mockImplementation(() => gate);

    const first = a.confirm({ ...ok, run });
    expect(a.writing).toBe(true);
    await a.confirm({ ...ok, run });
    expect(run).toHaveBeenCalledOnce();

    release();
    await first;
    expect(a.writing).toBe(false);
  });
});
