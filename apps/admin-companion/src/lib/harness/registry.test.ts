import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { buildRegistry } from './registry';
import { emptyAdminState } from './state';

/**
 * Registry coverage is ENFORCED (browser-harness.AC1.3): this test greps the live
 * `$lib/ipc.ts` source for every `invoke('…')` command name and asserts the fake
 * registry has a handler for each. A command added to `ipc.ts` without a handler fails
 * `pnpm test`. `plugin:event|*` names are excluded (handled by mockIPC's event mock);
 * `plugin:barcode-scanner|*` and `plugin:sharesheet|*` are reached through the plugins'
 * own SDKs (`scan()`, `shareText()`), not `invoke('…')`, so the grep never sees them.
 */
const here = dirname(fileURLToPath(import.meta.url));
const ipcFile = join(here, '..', 'ipc.ts');

function extractInvokedCommands(): Set<string> {
  const commands = new Set<string>();
  const pattern = /invoke(?:<[^>]*>)?\(\s*['"]([^'"]+)['"]/g;
  const source = readFileSync(ipcFile, 'utf8');
  for (const match of source.matchAll(pattern)) {
    const cmd = match[1];
    if (cmd.startsWith('plugin:event|')) continue;
    commands.add(cmd);
  }
  return commands;
}

describe('admin harness registry coverage', () => {
  const registry = buildRegistry(emptyAdminState());
  const handled = new Set(Object.keys(registry));

  it('finds a non-trivial IPC surface to check against', () => {
    expect(extractInvokedCommands().size).toBeGreaterThan(20);
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
