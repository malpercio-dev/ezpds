# ezpds interop CLI

Scripts for creating test accounts on an ezpds deployment and exercising its
interoperability with the **live ATProto network** — identity resolution
(plc.directory, well-known), repo CRUD, the firehose, sync/CAR export, relay
crawl status (bsky.network), AppView visibility (public.api.bsky.app), and
tightly-scoped social interactions.

Defaults target staging: `https://ezpds-staging.up.railway.app`.

## Ground rules (read first)

Staging is **not** an isolated sandbox — it federates with the production
ATProto network (real plc.directory, real relay, real AppView). The tools
therefore enforce:

- **Interaction allowlist.** The only external identity the tools will
  follow/like/mention is the operator's own — `did:web:malpercio.dev`
  (`@malpercio.dev`), hard-coded in `src/config.js`. Every such write is
  recorded in a local ledger and removed by `interact cleanup`.
- **Rate-limit respect.** All HTTP funnels through one paced client
  (≥350 ms between requests, `EZPDS_INTEROP_PACE_MS` to change) and honors
  `Retry-After` on 429. Sessions are cached and refreshed rather than
  re-created (`createSession` is limited to 30/5 min per IP).
- **Minimal PLC footprint.** Every account created registers a **permanent**
  `did:plc` in the global directory (deletion only removes the account from
  the PDS; the DID entry remains). Use one persistent account (`--name
  primary`) for routine runs; create `--ephemeral` accounts only for
  lifecycle tests, and tear them down with `delete-ephemeral`.

## Setup

```sh
cd tools/interop
pnpm install        # or: just interop-setup  (from the repo root)
```

Requirements: Node ≥ 22.12 (in the devenv shell). Environment:

| Variable | Purpose | Default |
|---|---|---|
| `EZPDS_BASE_URL` | Target PDS | `https://ezpds-staging.up.railway.app` |
| `EZPDS_ADMIN_TOKEN` | Mint claim codes (signup requires one) | unset |
| `EZPDS_INTEROP_PACE_MS` | Min gap between requests | `350` |
| `EZPDS_INTEROP_STATE_DIR` | State/credentials/reports dir | `tools/interop/.state` |

Without `EZPDS_ADMIN_TOKEN`, pass a pre-minted code to `create-account
--claim-code <code>`.

The `bin/interop` wrapper auto-configures Node for proxied environments
(`NODE_USE_ENV_PROXY`, `NODE_EXTRA_CA_CERTS`) — always invoke through it or
`just interop`.

## Quick start

```sh
just interop describe                      # server reachable? domains? invite required?
just interop create-account --name primary # one-time: canonical persistent account
just interop suite                         # full end-to-end run (includes interactions + cleanup)
just interop suite --no-interact           # same, but touches no external identity
just interop suite --lifecycle             # adds ephemeral create→deactivate→reap test
```

`suite` prints a pass/fail table and writes a JSON report under
`.state/reports/`. Exit code 0 = all steps passed.

## Migration testing

To test outbound migration (moving an account from one PDS to another), use the
`migrate` command group. This requires a **second PDS instance** (a separate
target deployment) and is **intentionally excluded from the default `suite`**.

**Prerequisites:**
- Two running PDS instances: the source (the default `EZPDS_BASE_URL`) and a
  separate target (passed with `--target-pds`).
- An existing account on the source PDS (create with `just interop
  create-account --name primary`).

**Commands:**

```sh
just interop migrate perform --name primary --target-pds https://target-pds.example.com
# Executes the complete 12-step migration:
# 1. Ensure source session
# 2. Describe target server
# 3. Reserve signing key on target
# 4. Get service auth token from source
# 5. Create account on target (with service auth)
# 6. Import repo from source to target
# 7. Drain blobs: list missing on target, fetch from source, upload to target
# 8. Copy preferences
# 9. Verify account status
# 10. Build and sign migration PLC operation with the local rotation key
# 11. Post signed op to plc.directory to repoint the DID
# 12. Activate account on target + deactivate on source; persist new PDS in state
```

After migration:

```sh
just interop migrate verify --name primary --target-pds https://target-pds.example.com
# Verifies the migration succeeded:
# - Handle resolves to the same DID
# - DID's plc.directory atproto_pds endpoint points to target PDS
# - Repo is serveable from the target PDS
```

**Note:** Once migration is complete, all subsequent interop commands for that
account automatically target the new PDS (via the `pds` field in
`.state/state.json`).

## What the suite checks

| Step | What it proves |
|---|---|
| health / describeServer | deployment up, config sane |
| ensure account | provisioning flow: claim code → mobile account → PDS repo-signing key → client-signed did:plc genesis op → handle → session |
| identity | `resolveHandle`, `/.well-known/atproto-did`, and the plc.directory DID doc all agree; PDS endpoint in the doc points at this deployment |
| CRUD | createRecord → getRecord (CID match) → listRecords → deleteRecord |
| firehose | a live `subscribeRepos` subscriber sees the `#commit` frame for a write, correct repo + op path |
| sync | CAR export parses, root CID == `getLatestCommit`, `getRepoStatus` active, repo in `listRepos` |
| network | relay (`bsky.network`) crawl status + AppView profile visibility — **informational** (staging may not be crawled); PDS→AppView service-proxy auth leg must pass |
| interact | resolve `@malpercio.dev` (did:web doc + PDS resolveHandle agree) → follow → like latest post → mention post → delete all of it |
| lifecycle | ephemeral account created, verified, deactivated with `deleteAfter`; the server reaper purges it (~5 min) and broadcasts `#account` deleted |

Individual steps are runnable standalone (`verify-identity`, `crud-test`,
`firehose-test`, `sync-test`, `network-check`, `interact …`) — see
`just interop help`.

## State & credentials

`.state/state.json` (gitignored, mode 0600) holds each account's password and
**did:plc rotation private key — the actual root of control for the DID**.
Losing it means losing the ability to ever update those DIDs; leaking it means
someone else can. Treat it like a key file. It also carries the interaction
ledger that `interact cleanup` works from.

## Cleanup guarantees

- `interact cleanup` deletes every ledgered interaction record; `suite` runs it
  as its own step and fails loudly if any deletion fails.
- Ephemeral accounts: `delete-ephemeral --name <n>` deactivates with a
  `deleteAfter` ≈5 min out; the PDS reaper then purges all server-side data and
  tells relays to drop the repo. The `did:plc` entry remains (wallet-native
  model: the rotation key in the state file could tombstone it, but the tools
  deliberately never write to plc.directory themselves).
