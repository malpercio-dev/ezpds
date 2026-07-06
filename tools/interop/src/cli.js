#!/usr/bin/env node
// ezpds interop CLI — see README.md for the runbook.

import { parseArgs } from 'node:util';
import { BASE_URL, ALLOWED_TARGET } from './config.js';
import { describeServer, health, createAccount, ensureSession, getSession, scheduleEphemeralDeletion, mintClaimCode } from './account.js';
import { verifyIdentity } from './identity.js';
import { createPost, crudRoundTrip, getRecord, listRecords, deleteRecord } from './records.js';
import { watchFirehose, firehoseWriteCheck } from './firehose.js';
import { syncChecks } from './sync.js';
import { networkChecks, relayHostStatus, appviewProfile } from './network.js';
import { resolveTarget, followTarget, likeTargetPost, mentionTarget, cleanupInteractions } from './interact.js';
import { performMigration, verifyMigration } from './migrate.js';
import { runSuite } from './suite.js';
import { loadState, statePaths } from './state.js';

const HELP = `ezpds interop CLI — exercises ${BASE_URL} against the live ATProto network.

Interaction scope is hard-limited to ${ALLOWED_TARGET.did} (${ALLOWED_TARGET.handle}).

Usage: interop <command> [flags]

Server
  describe                         health + describeServer
  claim-code                       mint one claim code (needs EZPDS_ADMIN_TOKEN)

Accounts (credentials persist in .state/state.json — gitignored)
  create-account --name <n> [--ephemeral] [--handle h] [--claim-code c]
  whoami --name <n>                getSession for the account
  accounts                         list accounts in local state
  delete-ephemeral --name <n> [--after-minutes m]   deactivate + schedule reaper purge

Checks
  verify-identity --name <n>       handle ↔ DID ↔ plc.directory agreement
  crud-test --name <n>             create/read/list/delete round-trip
  firehose-test --name <n>         write a post, observe its #commit frame
  sync-test --name <n>             CAR export, latestCommit, repoStatus, listRepos
  network-check --name <n>         relay crawl status + AppView visibility
  relay-status                     relay crawl status only
  appview-profile [--did d | --name <n>]   AppView profile lookup
  post --name <n> --text "..."     create a plain post (no mentions)
  get-record --did d --collection c --rkey r     read a single record
  list-records --did d [--collection c]          list records in a collection
  delete-record --name <n> --collection c --rkey r   delete a record
  firehose [--cursor c] [--seconds s]   stream frames to stdout

Interactions (only against ${ALLOWED_TARGET.handle}; all writes ledgered)
  interact resolve                 resolve + verify the allowed target
  interact follow --name <n>
  interact like --name <n>         like their latest post
  interact mention --name <n>      post mentioning them
  interact cleanup [--name <n>]    delete all ledgered interaction records

Migration (requires --target-pds; needs a second PDS instance; not part of suite)
  migrate perform --name <n> --target-pds <url>   drive outbound migration (self-signs PLC op)
  migrate verify --name <n> --target-pds <url>    confirm handle/DID/repo resolve to new PDS

Suite
  suite [--name <n>] [--no-interact] [--lifecycle]   full end-to-end run + JSON report

Environment: EZPDS_BASE_URL (default staging), EZPDS_ADMIN_TOKEN,
EZPDS_INTEROP_PACE_MS, EZPDS_INTEROP_STATE_DIR.
`;

function flags(args, extra = {}) {
  const { values } = parseArgs({
    args,
    options: {
      name: { type: 'string' },
      handle: { type: 'string' },
      'claim-code': { type: 'string' },
      'target-pds': { type: 'string' },
      'invite-code': { type: 'string' },
      ephemeral: { type: 'boolean' },
      lifecycle: { type: 'boolean' },
      'no-interact': { type: 'boolean' },
      'after-minutes': { type: 'string' },
      cursor: { type: 'string' },
      seconds: { type: 'string' },
      text: { type: 'string' },
      collection: { type: 'string' },
      rkey: { type: 'string' },
      did: { type: 'string' },
      ...extra,
    },
    allowPositionals: true,
  });
  return values;
}

function requireName(values) {
  if (!values.name) throw new Error('--name is required');
  return values.name;
}

const print = (data) => console.log(JSON.stringify(data, null, 2));

async function main() {
  const [command, ...rest] = process.argv.slice(2);
  // Subcommand must come immediately after the command (e.g. `interop interact follow --name x`).
  const sub = rest[0] && !rest[0].startsWith('--') ? rest[0] : undefined;
  const v = flags(rest);

  switch (command) {
    case 'describe':
      print({ health: await health(), server: await describeServer() });
      break;
    case 'claim-code':
      console.log(await mintClaimCode());
      break;
    case 'create-account': {
      const account = await createAccount({
        name: requireName(v),
        kind: v.ephemeral ? 'ephemeral' : 'persistent',
        handle: v.handle,
        claimCode: v['claim-code'],
      });
      print({ did: account.did, handle: account.handle, kind: account.kind });
      break;
    }
    case 'whoami':
      print(await getSession(requireName(v)));
      break;
    case 'accounts': {
      const state = loadState();
      print(Object.values(state.accounts).map(({ name, kind, did, handle, createdAt, scheduledDeletion }) =>
        ({ name, kind, did, handle, createdAt, scheduledDeletion })));
      console.error(`state file: ${statePaths().file}`);
      break;
    }
    case 'delete-ephemeral':
      print({ deleteAfter: await scheduleEphemeralDeletion(requireName(v), { afterMinutes: Number(v['after-minutes'] ?? 5) }) });
      break;
    case 'verify-identity':
      print(await verifyIdentity(requireName(v)));
      break;
    case 'crud-test':
      print(await crudRoundTrip(requireName(v)));
      break;
    case 'firehose-test': {
      const result = await firehoseWriteCheck(requireName(v));
      await deleteRecord(v.name, 'app.bsky.feed.post', result.rkey);
      print({ ...result, cleanedUp: true });
      break;
    }
    case 'sync-test':
      print(await syncChecks(requireName(v)));
      break;
    case 'network-check':
      print(await networkChecks(requireName(v)));
      break;
    case 'post': {
      if (!v.text) throw new Error('--text is required');
      if (v.text.includes('@')) throw new Error('plain post must not contain mentions; use "interact mention" for the allowlisted target');
      print(await createPost(requireName(v), v.text));
      break;
    }
    case 'get-record':
      print(await getRecord(v.did, v.collection, v.rkey));
      break;
    case 'list-records':
      print(await listRecords(v.did, v.collection ?? 'app.bsky.feed.post'));
      break;
    case 'delete-record':
      print(await deleteRecord(requireName(v), v.collection, v.rkey));
      break;
    case 'firehose':
      await watchFirehose({ cursor: v.cursor, seconds: Number(v.seconds ?? 30) });
      break;
    case 'relay-status':
      print(await relayHostStatus());
      break;
    case 'appview-profile':
      print(await appviewProfile(v.did ?? (await ensureSession(requireName(v))).did));
      break;
    case 'interact': {
      switch (sub) {
        case 'resolve': {
          const target = await resolveTarget();
          print({ did: target.did, handle: target.handle, pds: target.pds });
          break;
        }
        case 'follow': print(await followTarget(requireName(v))); break;
        case 'like': print(await likeTargetPost(requireName(v))); break;
        case 'mention': print(await mentionTarget(requireName(v))); break;
        case 'cleanup': print(await cleanupInteractions(v.name)); break;
        default: throw new Error(`unknown interact subcommand "${sub}" (resolve|follow|like|mention|cleanup)`);
      }
      break;
    }
    case 'migrate': {
      const targetPds = v['target-pds'];
      if (!targetPds) {
        throw new Error('migrate requires --target-pds <url> (needs a second PDS instance; not part of `suite`)');
      }
      switch (sub) {
        case 'perform': print(await performMigration({ name: requireName(v), targetPds })); break;
        case 'verify': print(await verifyMigration({ name: requireName(v), targetPds })); break;
        default: throw new Error(`unknown migrate subcommand "${sub}" (perform|verify)`);
      }
      break;
    }
    case 'suite': {
      const report = await runSuite({
        account: v.name ?? 'primary',
        interact: !v['no-interact'],
        lifecycle: Boolean(v.lifecycle),
      });
      process.exitCode = report.ok ? 0 : 1;
      break;
    }
    case 'help':
    case '--help':
    case undefined:
      console.log(HELP);
      break;
    default:
      console.error(`unknown command "${command}"\n`);
      console.log(HELP);
      process.exitCode = 2;
  }
}

main().catch((err) => {
  console.error(`error: ${err.message}`);
  process.exitCode = 1;
});
