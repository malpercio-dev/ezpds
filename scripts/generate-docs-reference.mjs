#!/usr/bin/env node

import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname, join, relative } from 'node:path';

const root = process.env.DOCS_SOURCE_ROOT ?? new URL('..', import.meta.url).pathname;
const outputRoot = process.env.DOCS_OUTPUT_ROOT ?? root;
const check = process.argv.includes('--check');

const read = (path) => readFileSync(join(root, path), 'utf8');
const version = read('Cargo.toml').match(/\[workspace\.package\][\s\S]*?\nversion\s*=\s*"([^"]+)"/)?.[1];
if (!version) throw new Error('workspace package version not found in Cargo.toml');

const frontmatter = (title, description) => `---\ntitle: ${title}\ndescription: ${description}\n---\n\n`;
const stamp = `> Generated from source for ezpds **v${version}**. Do not edit this page by hand.\n\n`;
const esc = (value) => value.replaceAll('|', '\\|').replaceAll('\n', ' ');

function apiReference() {
  const source = read('crates/pds/src/app.rs');
  const routes = [...source.matchAll(/\.route\(\s*"([^"]+)"/gs)].map((match) => match[1]);
  const unique = [...new Set(routes)].sort();
  if (unique.length === 0) throw new Error('no routes found in crates/pds/src/app.rs');
  return frontmatter('HTTP & XRPC API', 'Generated route reference for the Custos server.') + stamp
    + 'Every path registered by the server is listed here. For `/xrpc/` endpoints, use the namespace after `/xrpc/` to find the request, response, and authentication schema in the [AT Protocol Lexicon reference](https://docs.bsky.app/docs/api/at-protocol-xrpc-api). Custos-specific endpoints are explained in the operator workflows elsewhere in this documentation; this generated inventory is the complete route-coverage index.\n\n'
    + '| Registered path | Family |\n| --- | --- |\n'
    + unique.map((route) => `| \`${esc(route)}\` | ${route.startsWith('/xrpc/') ? 'AT Protocol XRPC' : 'Custos HTTP'} |`).join('\n') + '\n';
}

function parseConfigFields(source) {
  const fields = [];
  const structs = [...source.matchAll(/^(?:pub(?:\(crate\))?\s+)?struct\s+([A-Za-z0-9_]*Config)\s*\{\s*\n([\s\S]*?)^\}/gm)];
  for (const [, structName, body] of structs) {
    if (structName.startsWith('Raw')) continue;
    let docs = [];
    for (const line of body.split('\n')) {
      const doc = line.match(/^\s*\/\/\/\s?(.*)$/);
      if (doc) { docs.push(doc[1]); continue; }
      if (/^\s*#\[/.test(line) || /^\s*\/\//.test(line) || /^\s*$/.test(line)) continue;
      const field = line.match(/^\s*pub(?:\(crate\))?\s+([A-Za-z0-9_]+)\s*:\s*([^,]+),/);
      if (field) {
        fields.push({ structName, name: field[1], type: field[2].trim(), docs: docs.join(' ') || 'No field-level description.' });
      }
      docs = [];
    }
  }
  return fields;
}

function configReference() {
  const source = read('crates/common/src/config.rs');
  const fields = parseConfigFields(source);
  if (fields.length === 0) throw new Error('no public configuration fields found');
  const env = [...new Set([...source.matchAll(/env\.get\("([A-Z][A-Z0-9_]+)"\)/g)].map((match) => match[1]))].sort();
  if (!env.includes('EZPDS_DATA_DIR')) throw new Error('environment override registry could not be extracted');
  const sectionByType = new Map(fields.filter(({ structName }) => structName === 'Config').map(({ name, type }) => [type, name]));
  const envByPath = new Map();
  for (const match of source.matchAll(/env\.get\("([A-Z][A-Z0-9_]+)"\)/g)) {
    const block = source.slice(match.index, source.indexOf('\n    if let Some', match.index + 1));
    const assignment = block.match(/raw\.([A-Za-z0-9_.]+)\s*=/)?.[1];
    if (assignment) envByPath.set(assignment, [...(envByPath.get(assignment) ?? []), match[1]]);
  }
  const pathFor = ({ structName, name }) => structName === 'Config' ? name : `${sectionByType.get(structName) ?? structName}.${name}`;
  const mappedEnv = new Set([...envByPath.values()].flat());
  const standaloneEnv = env.filter((name) => !mappedEnv.has(name));
  return frontmatter('Configuration reference', 'Generated TOML fields and environment controls for Custos operators.') + stamp
    + 'Fields come from the validated Rust configuration types. Environment overrides come from the loader and are shown beside the TOML value they replace. A dash means that field has no direct environment override. Sensitive values are named but never rendered.\n\n'
    + '## TOML fields and overrides\n\n| TOML key | Environment override | Rust type | Source description |\n| --- | --- | --- | --- |\n'
    + fields.map((field) => { const path = pathFor(field); const overrides = envByPath.get(path) ?? []; return `| \`${path}\` | ${overrides.length ? overrides.map((name) => `\`${name}\``).join(', ') : '—'} | \`${esc(field.type)}\` | ${esc(field.docs)} |`; }).join('\n')
    + '\n\n## Process-level environment variables\n\n'
    + standaloneEnv.map((name) => `- \`${name}\``).join('\n') + (standaloneEnv.length ? '\n' : '')
    + '- `EZPDS_CONFIG` — path to the TOML configuration file (CLI source).\n';
}

function ipcCommands(path) {
  const source = read(path);
  return [...source.matchAll(/invoke(?:<[^;()]+>)?\(\s*['"]([^'"]+)['"]/g)].map((match) => match[1]);
}

function ipcReference() {
  const walletIndex = read('apps/identity-wallet/src/lib/ipc/index.ts');
  const modules = [...walletIndex.matchAll(/from\s+['"]\.\/([^'"]+)['"]/g)].map((match) => `apps/identity-wallet/src/lib/ipc/${match[1]}.ts`);
  const wallet = [...new Set(modules.flatMap(ipcCommands))].sort();
  const admin = [...new Set(ipcCommands('apps/admin-companion/src/lib/ipc.ts'))].sort();
  if (wallet.length === 0 || admin.length === 0) throw new Error('IPC command registry could not be extracted for both apps');
  const section = (title, sourcePath, commands) => `## ${title}\n\nSource: \`${sourcePath}\`\n\n| Command | Kind |\n| --- | --- |\n${commands.map((command) => `| \`${command}\` | ${command.startsWith('plugin:') ? 'Tauri plugin' : 'App command'} |`).join('\n')}\n`;
  return frontmatter('Mobile IPC commands', 'Generated Tauri command surface for Obsign and Brass Console.') + stamp
    + 'These are the literal commands invoked by each frontend registry.\n\n'
    + section('Obsign identity wallet', 'apps/identity-wallet/src/lib/ipc/', wallet) + '\n'
    + section('Brass Console', 'apps/admin-companion/src/lib/ipc.ts', admin);
}

const pages = new Map([
  ['sites/docs/src/content/docs/operator/reference/api.md', apiReference()],
  ['sites/docs/src/content/docs/operator/reference/config.md', configReference()],
  ['sites/docs/src/content/docs/operator/reference/ipc.md', ipcReference()],
]);

let stale = false;
for (const [path, content] of pages) {
  const target = join(outputRoot, path);
  if (check) {
    let current = '';
    try { current = readFileSync(target, 'utf8'); } catch {}
    if (current !== content) {
      console.error(`✗ generated docs are stale: ${relative(outputRoot, target)} (run just docs-generate)`);
      stale = true;
    }
  } else {
    mkdirSync(dirname(target), { recursive: true });
    writeFileSync(target, content);
    console.log(`generated ${relative(outputRoot, target)}`);
  }
}

if (stale) process.exit(1);
if (check) console.log(`✓ docs parity: ${pages.size} generated reference pages match routes, config, IPC, and v${version}`);
