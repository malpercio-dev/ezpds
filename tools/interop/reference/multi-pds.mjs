// The reference multi-PDS network on configurable ports: dev-env's `bin-multi-pds` setup
// (local PLC, a lex-authority account, a primary PDS + extras, seeded alice/bob/carol),
// rebuilt on dev-env's exported TestPlc/TestPds API because `bin-multi-pds` hard-codes
// ports 2581–2583, which collide with any other dev-env left running. The introspection
// server is left out; nothing here uses it.
//
//   node multi-pds.mjs <atproto-checkout> <pds-count> <base-port>
//
// PLC listens on <base-port>, PDS i on <base-port> + i. Prints `PLC <url>`, one
// `PDS<i> <url>` line per PDS, the seeded accounts, then `ready`.

import path from 'node:path';
import { pathToFileURL } from 'node:url';

const [src, countArg = '2', baseArg = '2680'] = process.argv.slice(2);
const count = Number.parseInt(countArg, 10);
const base = Number.parseInt(baseArg, 10);
if (!src || !(count >= 1) || !(base > 0)) {
  console.error('usage: multi-pds.mjs <atproto-checkout> <pds-count> <base-port>');
  process.exit(2);
}

const dist = path.join(src, 'packages/dev-env/dist');
const { TestPlc, TestPds, mockNetworkUtilities, mockMailer } = await import(pathToFileURL(path.join(dist, 'index.js')).href);
const { LexiconAuthorityProfile } = await import(pathToFileURL(path.join(dist, 'service-profile-lexicon.js')).href);

const LEX_AUTHORITY_USER = { email: 'lex-authority@test.com', handle: 'lex-authority.test', password: 'hunter2' };

const plc = await TestPlc.create({ port: base });

// Same order as bin-multi-pds: the lex-authority account is born on a scratch PDS so its
// DID exists before the real PDSes are configured to resolve lexicons from it.
const scratch = await TestPds.create({ didPlcUrl: plc.url, inviteRequired: false });
const lexAuthority = await LexiconAuthorityProfile.create(scratch, LEX_AUTHORITY_USER);

const pdses = [
  await TestPds.create({
    port: base + 1,
    hostname: 'localhost',
    enableDidDocWithSession: true,
    didPlcUrl: plc.url,
    lexiconDidAuthority: lexAuthority.did,
  }),
];
await lexAuthority.migrateTo(pdses[0]);
await lexAuthority.createRecords();
for (let i = 2; i <= count; i++) {
  pdses.push(await TestPds.create({
    port: base + i,
    didPlcUrl: plc.url,
    serviceHandleDomains: [`.test${i}`],
    lexiconDidAuthority: lexAuthority.did,
  }));
}
await scratch.close();

mockNetworkUtilities(pdses);
for (const pds of pdses) mockMailer(pds);

console.log(`PLC ${plc.url}`);
pdses.forEach((pds, i) => console.log(`PDS${i + 1} ${pds.url}`));
console.log(`lex authority ${LEX_AUTHORITY_USER.handle} ${lexAuthority.did} (password ${LEX_AUTHORITY_USER.password}, on PDS1)`);

for (const [i, pds] of pdses.entries()) {
  const domain = i === 0 ? 'test' : `test${i + 1}`;
  for (const name of ['alice', 'bob', 'carol']) {
    const res = await pds.getAgent().com.atproto.server.createAccount({
      handle: `${name}.${domain}`,
      email: `${name}-${domain}@test.com`,
      password: `${name}-pass`,
    });
    console.log(`seeded PDS${i + 1} ${name}.${domain} ${res.data.did} (password ${name}-pass)`);
  }
}
console.log('ready');
