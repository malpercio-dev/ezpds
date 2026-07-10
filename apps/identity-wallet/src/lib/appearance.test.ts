import { describe, it, expect, vi, beforeEach } from 'vitest';
import { normalizePreference, toColorScheme } from './appearance';

describe('normalizePreference', () => {
  it('passes through the two override values', () => {
    expect(normalizePreference('light')).toBe('light');
    expect(normalizePreference('dark')).toBe('dark');
  });

  it('maps system to system', () => {
    expect(normalizePreference('system')).toBe('system');
  });

  it('coerces anything unrecognized to system', () => {
    expect(normalizePreference(null)).toBe('system');
    expect(normalizePreference(undefined)).toBe('system');
    expect(normalizePreference('')).toBe('system');
    expect(normalizePreference('sepia')).toBe('system');
    expect(normalizePreference('DARK')).toBe('system');
    expect(normalizePreference(42)).toBe('system');
  });
});

describe('toColorScheme', () => {
  it('maps system to the empty override (follow the system)', () => {
    expect(toColorScheme('system')).toBe('');
  });

  it('maps light and dark to themselves', () => {
    expect(toColorScheme('light')).toBe('light');
    expect(toColorScheme('dark')).toBe('dark');
  });
});

// ── Stateful paths (initAppearance / setAppearance) ────────────────────────
//
// appearance.ts carries module-level ordering state (revision counter,
// persist chain), so each test loads a fresh copy via vi.resetModules() +
// dynamic import, with the IPC layer mocked and minimal document/localStorage
// stubs (vitest runs in a node environment).

type Ipc = {
  getAppearancePreference: ReturnType<typeof vi.fn>;
  setAppearancePreference: ReturnType<typeof vi.fn>;
};

function stubDom() {
  const store = new Map<string, string>();
  vi.stubGlobal('localStorage', {
    getItem: (k: string) => store.get(k) ?? null,
    setItem: (k: string, v: string) => void store.set(k, String(v)),
    removeItem: (k: string) => void store.delete(k),
  });
  const documentStub = { documentElement: { style: { colorScheme: '' } } };
  vi.stubGlobal('document', documentStub);
  return { store, documentStub };
}

async function loadAppearance(ipc: Ipc) {
  vi.doMock('$lib/ipc', () => ipc);
  return await import('./appearance');
}

/** Drain microtasks (and one macrotask) so queued persist steps can start. */
function nextTick() {
  return new Promise<void>((resolve) => setTimeout(resolve, 0));
}

/** A promise the test resolves/rejects by hand, to control IPC timing. */
function deferred<T>() {
  let resolve!: (v: T) => void;
  let reject!: (e: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

beforeEach(() => {
  vi.resetModules();
  vi.unstubAllGlobals();
  vi.clearAllMocks();
});

describe('initAppearance', () => {
  it('lets the Keychain win over a stale mirror and updates the mirror', async () => {
    const { store, documentStub } = stubDom();
    store.set('appearance-preference', 'light');
    const ipc: Ipc = {
      getAppearancePreference: vi.fn().mockResolvedValue('dark'),
      setAppearancePreference: vi.fn(),
    };
    const { initAppearance } = await loadAppearance(ipc);

    await expect(initAppearance()).resolves.toBe('dark');
    expect(documentStub.documentElement.style.colorScheme).toBe('dark');
    expect(store.get('appearance-preference')).toBe('dark');
  });

  it('removes the mirror when the Keychain says system', async () => {
    const { store, documentStub } = stubDom();
    store.set('appearance-preference', 'dark');
    const ipc: Ipc = {
      getAppearancePreference: vi.fn().mockResolvedValue(null),
      setAppearancePreference: vi.fn(),
    };
    const { initAppearance } = await loadAppearance(ipc);

    await expect(initAppearance()).resolves.toBe('system');
    expect(documentStub.documentElement.style.colorScheme).toBe('');
    expect(store.has('appearance-preference')).toBe(false);
  });

  it('keeps the mirror when the Keychain is unreadable', async () => {
    const { store, documentStub } = stubDom();
    store.set('appearance-preference', 'dark');
    const ipc: Ipc = {
      getAppearancePreference: vi.fn().mockRejectedValue({ code: 'KEYCHAIN_ERROR' }),
      setAppearancePreference: vi.fn(),
    };
    const { initAppearance } = await loadAppearance(ipc);

    await expect(initAppearance()).resolves.toBe('dark');
    expect(documentStub.documentElement.style.colorScheme).toBe('dark');
    expect(store.get('appearance-preference')).toBe('dark');
  });

  it('never clobbers a choice made while the Keychain read was in flight', async () => {
    const { store, documentStub } = stubDom();
    const read = deferred<string>();
    const ipc: Ipc = {
      getAppearancePreference: vi.fn().mockReturnValue(read.promise),
      setAppearancePreference: vi.fn().mockResolvedValue(undefined),
    };
    const { initAppearance, setAppearance } = await loadAppearance(ipc);

    const init = initAppearance();
    await setAppearance('dark'); // user picks before the stored value arrives
    read.resolve('light'); // ...then the older stored value lands

    await expect(init).resolves.toBe('dark');
    expect(documentStub.documentElement.style.colorScheme).toBe('dark');
    expect(store.get('appearance-preference')).toBe('dark');
  });
});

describe('setAppearance', () => {
  it('applies to the document and mirror before the Keychain write resolves', async () => {
    const { store, documentStub } = stubDom();
    const write = deferred<void>();
    const ipc: Ipc = {
      getAppearancePreference: vi.fn().mockResolvedValue(null),
      setAppearancePreference: vi.fn().mockReturnValue(write.promise),
    };
    const { setAppearance } = await loadAppearance(ipc);

    const pending = setAppearance('dark');
    expect(documentStub.documentElement.style.colorScheme).toBe('dark');
    expect(store.get('appearance-preference')).toBe('dark');

    write.resolve();
    await expect(pending).resolves.toBeUndefined();
  });

  it('system removes the mirror entry', async () => {
    const { store } = stubDom();
    store.set('appearance-preference', 'dark');
    const ipc: Ipc = {
      getAppearancePreference: vi.fn().mockResolvedValue('dark'),
      setAppearancePreference: vi.fn().mockResolvedValue(undefined),
    };
    const { setAppearance } = await loadAppearance(ipc);

    await setAppearance('system');
    expect(store.has('appearance-preference')).toBe(false);
  });

  it('rolls the mirror back to the last persisted value on a failed write, keeping the on-screen choice', async () => {
    const { store, documentStub } = stubDom();
    store.set('appearance-preference', 'light');
    const ipc: Ipc = {
      getAppearancePreference: vi.fn().mockResolvedValue('light'),
      setAppearancePreference: vi.fn().mockRejectedValue({ code: 'KEYCHAIN_ERROR' }),
    };
    const { initAppearance, setAppearance } = await loadAppearance(ipc);
    await initAppearance(); // establishes 'light' as the last persisted value

    await expect(setAppearance('dark')).rejects.toEqual({ code: 'KEYCHAIN_ERROR' });
    // Session keeps the choice; the next launch paints the durable state.
    expect(documentStub.documentElement.style.colorScheme).toBe('dark');
    expect(store.get('appearance-preference')).toBe('light');
  });

  it('skips a write that is superseded before it starts — only the newest hits the Keychain', async () => {
    const { store } = stubDom();
    const calls: string[] = [];
    const ipc: Ipc = {
      getAppearancePreference: vi.fn().mockResolvedValue(null),
      setAppearancePreference: vi.fn().mockImplementation((preference: string) => {
        calls.push(preference);
        return Promise.resolve();
      }),
    };
    const { setAppearance } = await loadAppearance(ipc);

    // Same synchronous turn: the second selection lands before the first
    // queued write has started, so the first is skipped outright.
    const first = setAppearance('light');
    const second = setAppearance('dark');

    await Promise.all([first, second]);
    expect(calls).toEqual(['dark']);
    expect(store.get('appearance-preference')).toBe('dark');
  });

  it('serializes an in-flight write with a newer one so the newest persists last', async () => {
    const { store } = stubDom();
    const firstWrite = deferred<void>();
    const calls: string[] = [];
    const ipc: Ipc = {
      getAppearancePreference: vi.fn().mockResolvedValue(null),
      setAppearancePreference: vi.fn().mockImplementation((preference: string) => {
        calls.push(preference);
        return calls.length === 1 ? firstWrite.promise : Promise.resolve();
      }),
    };
    const { setAppearance } = await loadAppearance(ipc);

    const first = setAppearance('light');
    await nextTick(); // let the first write actually start (and hang on IPC)
    const second = setAppearance('dark');
    firstWrite.resolve(); // the slow older write finishes only now

    await Promise.all([first, second]);
    expect(calls).toEqual(['light', 'dark']); // strictly ordered — newest wins in the Keychain
    expect(store.get('appearance-preference')).toBe('dark');
  });

  it('a failed superseded write does not roll back the newer selection', async () => {
    const { store } = stubDom();
    const firstWrite = deferred<void>();
    let call = 0;
    const ipc: Ipc = {
      getAppearancePreference: vi.fn().mockResolvedValue(null),
      setAppearancePreference: vi.fn().mockImplementation(() => {
        call += 1;
        return call === 1 ? firstWrite.promise : Promise.resolve();
      }),
    };
    const { setAppearance } = await loadAppearance(ipc);

    const first = setAppearance('light');
    await nextTick(); // first write is now in flight
    const second = setAppearance('dark');
    firstWrite.reject({ code: 'KEYCHAIN_ERROR' }); // older write fails after being superseded

    await expect(first).rejects.toEqual({ code: 'KEYCHAIN_ERROR' });
    await expect(second).resolves.toBeUndefined();
    expect(store.get('appearance-preference')).toBe('dark');
  });
});
