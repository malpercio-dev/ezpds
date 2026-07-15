import { describe, it, expect } from 'vitest';
import { readdirSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { buildRegistry } from './registry';
import { emptyWalletState } from './state';

/**
 * Registry coverage is ENFORCED, not aspirational (browser-harness.AC1.3): this test
 * greps the live `$lib/ipc` source for every `invoke('…')` command name and asserts the
 * fake registry has a handler for each. Adding a command to `ipc.ts` without a handler
 * fails `pnpm test` — the harness can never silently drift behind the IPC surface.
 *
 * `plugin:event|*` names are excluded: those are handled by mockIPC's own event mock
 * (`shouldMockEvents`), not the registry.
 */
const here = dirname(fileURLToPath(import.meta.url));
const ipcDir = join(here, '..', 'ipc');

function extractInvokedCommands(): Set<string> {
  const commands = new Set<string>();
  // Match `invoke('cmd'`, `invoke<T>('cmd'`, `invoke("cmd"` across the ipc modules.
  const pattern = /invoke(?:<[^>]*>)?\(\s*['"]([^'"]+)['"]/g;
  for (const file of readdirSync(ipcDir)) {
    if (!file.endsWith('.ts') || file.endsWith('.test.ts')) continue;
    const source = readFileSync(join(ipcDir, file), 'utf8');
    for (const match of source.matchAll(pattern)) {
      const cmd = match[1];
      if (cmd.startsWith('plugin:event|')) continue;
      commands.add(cmd);
    }
  }
  return commands;
}

describe('wallet harness registry coverage', () => {
  const registry = buildRegistry(emptyWalletState());
  const handled = new Set(Object.keys(registry));

  it('finds a non-trivial IPC surface to check against', () => {
    expect(extractInvokedCommands().size).toBeGreaterThan(30);
  });

  it('has a fake handler for every command the frontend invokes', () => {
    const missing = [...extractInvokedCommands()].filter((cmd) => !handled.has(cmd));
    expect(missing, `commands with no harness handler: ${missing.join(', ')}`).toEqual([]);
  });

  it('every registered handler is callable', () => {
    for (const [name, handler] of Object.entries(registry)) {
      expect(typeof handler, name).toBe('function');
    }
  });
});
