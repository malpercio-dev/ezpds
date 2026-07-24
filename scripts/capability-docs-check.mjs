#!/usr/bin/env node
// Guard the operator capability documentation against drift from the source of truth.
//
// `crates/pds/src/capabilities.rs` decides what `describeServer` advertises under the
// `custos` extension and — through each entry's `control` field — which configuration
// decides whether a capability is offered. That is what an operator needs to know and
// what a client feature-gates on, so it must be documented; and a *stale* description of
// how a capability is switched on is worse than none, because an operator will act on it.
//
// This check enforces three things, all read from the Rust table rather than restated:
//   1. every capability has a section on the operator capabilities page;
//   2. that section's `**Controlled by:**` line names every control the Rust entry
//      declares (a config field path, or `always` for an inherent capability);
//   3. the page documents no capability the server does not advertise.
//
// A new capability, a renamed config knob, or a capability whose gate moved therefore
// fails CI until the operator page moves with it. The generated reference page
// (operator/reference/capabilities.md) is covered separately by `just docs-check`.

import { readFileSync } from 'node:fs';
import { join } from 'node:path';

const root = new URL('..', import.meta.url).pathname;
const read = (path) => readFileSync(join(root, path), 'utf8');

const SOURCE = 'crates/pds/src/capabilities.rs';
const OPERATOR_PAGE = 'sites/docs/src/content/docs/operator/capabilities.md';
const GENERATED_PAGE = 'sites/docs/src/content/docs/operator/reference/capabilities.md';
const CONTROLLED_BY = '**Controlled by:**';

/** Parse the `CAPABILITIES` table into `{ name, controls[] }` entries. */
function parseCapabilities(source) {
  const table = source.match(/pub const CAPABILITIES: &\[Capability\] = &\[([\s\S]*?)\n\];/);
  if (!table) throw new Error(`could not find the CAPABILITIES table in ${SOURCE}`);
  const entries = [
    ...table[1].matchAll(
      /name:\s*"([^"]+)",\s*\n\s*control:\s*(?:CONTROL_ALWAYS|"([^"]*)"),/g,
    ),
  ].map(([, name, control]) => ({
    name,
    // CONTROL_ALWAYS (no string literal captured) is the "no operator switch" sentinel.
    controls: (control ?? 'always').split(/\s+/).filter(Boolean),
  }));
  if (entries.length === 0) throw new Error(`no capability entries parsed from ${SOURCE}`);
  return entries;
}

/** Split a markdown page into `### \`name\`` sections keyed by the quoted heading text. */
function parseSections(page) {
  const sections = new Map();
  const headings = [...page.matchAll(/^###\s+`([^`]+)`\s*$/gm)];
  for (const [index, heading] of headings.entries()) {
    const start = heading.index + heading[0].length;
    const end = index + 1 < headings.length ? headings[index + 1].index : page.length;
    sections.set(heading[1], page.slice(start, end));
  }
  return sections;
}

const capabilities = parseCapabilities(read(SOURCE));
const sections = parseSections(read(OPERATOR_PAGE));
const generated = read(GENERATED_PAGE);

const problems = [];

for (const { name, controls } of capabilities) {
  const section = sections.get(name);
  if (section === undefined) {
    problems.push(
      `capability \`${name}\` is advertised by the server but has no "### \`${name}\`" section in ${OPERATOR_PAGE}`,
    );
    continue;
  }

  // The whole paragraph, not one line: prose wraps, and a control list is routinely
  // longer than a line.
  const controlParagraph = section
    .split(/\n\s*\n/)
    .map((paragraph) => paragraph.trim())
    .find((paragraph) => paragraph.startsWith(CONTROLLED_BY));
  if (controlParagraph === undefined) {
    problems.push(
      `capability \`${name}\`'s section in ${OPERATOR_PAGE} has no "${CONTROLLED_BY}" line saying how an operator switches it`,
    );
    continue;
  }

  for (const control of controls) {
    if (!controlParagraph.includes(control)) {
      problems.push(
        `capability \`${name}\` is gated on \`${control}\` in ${SOURCE}, but its "${CONTROLLED_BY}" line in ${OPERATOR_PAGE} does not mention it:\n    ${controlParagraph.replace(/\s+/g, " ")}`,
      );
    }
  }

  if (!generated.includes(`\`${name}\``)) {
    problems.push(
      `capability \`${name}\` is missing from the generated reference page ${GENERATED_PAGE} (run \`just docs-generate\`)`,
    );
  }
}

const known = new Set(capabilities.map(({ name }) => name));
for (const name of sections.keys()) {
  if (!known.has(name)) {
    problems.push(
      `${OPERATOR_PAGE} documents a capability \`${name}\` that ${SOURCE} does not advertise — remove the section, or add the capability`,
    );
  }
}

if (problems.length > 0) {
  for (const problem of problems) console.error(`✗ capability-docs: ${problem}`);
  console.error(
    `\nThe capability table in ${SOURCE} is the source of truth for what Custos advertises and\nhow each capability is controlled. Update ${OPERATOR_PAGE} in the same change (and run\n\`just docs-generate\` for the reference table).`,
  );
  process.exit(1);
}

console.log(
  `✓ capability docs: ${capabilities.length} advertised capabilities documented with matching controls`,
);
