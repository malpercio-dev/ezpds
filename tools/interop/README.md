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
| `EZPDS_PLC_URL` | PLC directory (e.g. the reference PDS's local PLC) | `https://plc.directory` |
| `EZPDS_INTEROP_PACE_MS` | Min gap between requests | `350` |
| `EZPDS_INTEROP_STATE_DIR` | State/credentials/reports dir | `tools/interop/.state` |

Without `EZPDS_ADMIN_TOKEN`, pass a pre-minted code to `create-account
--claim-code <code>`.

`just interop-test` unit-checks the pure pieces offline (DPoP proof construction, STAR
parsing); everything else is exercised by running the commands against a deployment.

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

**Note:** `migrate perform` records the new endpoint on the account (`pds` +
`migrationStatus` in `.state/state.json`) and stores the destination session, but
the other interop commands (`account`, `sync`, `records`, the `suite`) still target
the configured `BASE_URL` — they do **not** yet read the per-account `pds`. Use
`migrate verify --target-pds <url>` (which takes the destination explicitly) to
confirm the migrated account on the new PDS.

## Reference PDS

The Spaces conformance target is the reference implementation at a frozen commit: atproto
`permissioned-data` @ `355b73380411a24c751b9896ee9e17f5b593bca7`. `just reference-pds` builds
it **from source** at that commit and runs `packages/dev-env`'s multi-PDS setup through
`reference/multi-pds.mjs` (see "Why not `bin-multi-pds`" below). It never
uses `latest` or an image tag. Moving the pin is a decision with its own ticket, so the SHA
is a constant in `bin/reference-pds`.

```sh
just reference-pds            # build if needed, then serve 2 PDSes + a local PLC (Ctrl-C stops)
just reference-pds up 3       # 3 PDSes
just reference-pds smoke      # start, run create-account + crud-test on every PDS, stop
just reference-pds build      # clone/fetch, check out + verify the pin, install, build
just reference-pds spaces     # + a local Custos: the cross-host Spaces scenario both ways
just reference-pds spaces-up  # the same network, left up (see "The cross-host scenario")
```

`up` prints the hosts: PLC on `http://localhost:2680`, then PDS *i* on `2680 + i`.
`EZPDS_REFERENCE_PORT` moves the base port. It also seeds `alice`/`bob`/`carol` on each
PDS (`<name>-pass`; handles `.test` on PDS1, `.test2` on PDS2, and so on). Point the CLI
at them with the account's `--host` and the local PLC:

```sh
export EZPDS_PLC_URL=http://localhost:2680 EZPDS_INTEROP_PACE_MS=0
just interop create-account --name ref1 --host http://localhost:2681   # standard createAccount
just interop crud-test --name ref1
just interop import-session --name alice --host http://localhost:2681 \
  --identifier alice.test --password alice-pass                        # a seeded account
```

`create-account --host` uses standard `com.atproto.server.createAccount`, not the Custos
`/v1/*` ceremony. The PDS mints the did:plc, and the command reads the DID document back
from `EZPDS_PLC_URL` and requires it to name that host. Defaults are unchanged: without
`--host` and `EZPDS_PLC_URL`, everything still targets staging and plc.directory.

### Why not `bin-multi-pds`

dev-env ships the same network as `pnpm start:multi-pds` (`dist/bin-multi-pds.js`), but it
hard-codes ports 2581 (introspection), 2582 (PLC) and 2583 (primary PDS). Any other
atproto dev-env left running on the machine already holds them, and the startup dies with
`EADDRINUSE`. `reference/multi-pds.mjs` builds the same setup from dev-env's exported API
(`TestPlc`, `TestPds`, `LexiconAuthorityProfile`, `mockNetworkUtilities`, `mockMailer`) in
the same order: a local PLC, a lex-authority account born on a scratch PDS, a primary PDS
plus extras that resolve lexicons from it, and the seeded accounts. The only differences
are ports chosen by the caller and no introspection server. The atproto checkout is never
patched, so the pin stays the reference as published.

Gotchas:

- **Toolchain.** The pinned repo requires pnpm 12 (`packageManager`) and Node `^22.23.4`
  (`devEngines`, `onFail: error`). The script fetches pnpm 12 with corepack into the cache.
  It runs the devenv's Node 22.22 with `pnpm_config_runtime_on_fail=ignore`, because letting
  pnpm download a runtime picks Node 26, and better-sqlite3 has no build for it.
- **Ports.** The script checks that the PLC port and every PDS port are free before it
  starts. If one is taken, set `EZPDS_REFERENCE_PORT` to another base port.
- **Cache.** The clone and build live in `~/.cache/ezpds/reference-pds`
  (`EZPDS_REFERENCE_CACHE` overrides). A `built` stamp holding the pin skips the cold build
  (several minutes) on later runs. Delete the stamp to force a rebuild.
- **Ephemeral.** Every PDS and the PLC keep their data in temp dirs, so stopping the
  process discards all accounts. `smoke` uses a throwaway state dir for the same reason.
  For manual runs, reuse `--name`s only within one `up`, or point
  `EZPDS_INTEROP_STATE_DIR` somewhere disposable.
- **Handles.** The handles are `.test`/`.test2`/…, which only the dev-env's in-process
  mocks resolve. `verify-identity` (HTTPS well-known handle resolution) therefore cannot
  pass here. The PLC check in `create-account --host` covers the identity leg.

## Atproto Spaces

Four commands:

```sh
just interop spaces-test --name primary          # authority = self, one host
just interop spaces-allowlist --name primary     # allowedApps refuses authorizeSpaceSync without an attestation
just interop spaces-interop --authority a --member b   # the cross-host scenario, two hosts
just interop spaces-vectors                      # the crypto crate's MAC vectors, recomputed by the reference
```

`spaces-test` is the single-host round-trip: `createSpace` → `createRecord` →
get/list/listSpaces → `getLatestCommit`/`listRepoOps`/`getRepo` → teardown, reading the export
as a parsed STAR archive. `spaces-allowlist` checks that an `allowedApps` space answers
`AppNotAuthorized` to an `authorizeSpaceSync` naming no client, the authority's own request
included. Both run against any deployment, so `suite` includes them.

### The cross-host scenario

`spaces-interop` is the check that defines conformance: Custos against the reference built from
source at the pin, in both directions. One command stands up the network and runs it:

```sh
cargo build -p pds            # the scenario runs the debug binary
just reference-pds spaces     # reference + local Custos on one PLC, scenario both ways, stop
```

`just reference-pds spaces-up` keeps the network up instead and writes `<dir>/env`. Source it,
create the accounts, and run each direction yourself:

```sh
. <dir>/env
just interop create-account --name custos                              # on the local Custos
just interop create-account --name ref --host "$EZPDS_REFERENCE_URL"   # on the reference
just interop spaces-interop --authority custos --member ref
just interop spaces-interop --authority ref --member custos
```

The authority hosts a memberspace and the member writes into it from its own host. Each step
is reported pass or fail, and a failed step does not stop the ones that don't depend on it:

1. **identity.** Both DID documents publish `#atproto_kem`.
2. **policy.** `createSpace` with `publishPolicy`/`publishMembers`, `putMembers` for the member,
   then the published `com.atproto.space.policy` and member records and `listMembers`.
3. **credential.** A delegation token from the member's host, spent at the authority's
   `authorizeSpaceSync` with a fresh P-256 `credentialKey` and a `notify` registration. The
   scenario serves the syncer endpoint on `localhost` and must see `confirmRegistration`.
4. **write** and **moderation.** The member writes a note and a `com.atproto.label.record`
   into the foreign space, and the authority's registered syncer receives a `repoWrite`.
5. **MAC** and **STAR.** Credential-authed `getRecord`, `getLatestCommit`, `listRepoOps` and
   `getRepo` on the member's host, each with `Accept-Signature` under a fresh key share
   encapsulated to the member's published `#atproto_kem`. Each MAC is verified, and `getRepo`
   is checked with the LtHash recomputed against the commit's `data`. An unsigned credential
   must be refused.
6. **authority reads.** A credential-authed, MAC-verified read of the policy record on the
   authority, then `listWriters` with the member's commit digest.
7. **writer set.** `removeWriter` → `listWriters` shows `repoRemoved` (and the syncer is told);
   `clearRecords` → the empty LtHash digest.
8. **migration.** A throwaway authority's space moves to the other host the way an account
   migration carries it: `reserveSigningKey` and `createAccount` under service auth, then
   `exportSpaceMeta` → `importSpaceMeta` and `getRepo` → `importRepo`, and the digests must
   match. The account stays deactivated there.
9. **vectors.** As `spaces-vectors`.

Every MAC, STAR archive and LtHash is checked with the reference's own `@atproto/space` from
the `bin/reference-pds build` checkout, not this tool's code.

How the network is wired (`bin/reference-pds`, `reference/custos-local.mjs`):

- **One PLC.** Custos registers its DIDs with the reference's local PLC, so each side
  resolves the other's DID documents.
- **TLS for Custos.** Custos needs an https public URL. It sits behind a TLS proxy on
  `https://localhost:2690` (`EZPDS_CUSTOS_PORT`) with a throwaway cert. The reference and the
  CLI trust that cert through `NODE_EXTRA_CA_CERTS`.
- **Loopback for Custos.** Custos reaches the reference's http loopback PDS through its
  SSRF-hardened client only because `EZPDS_DEV_ALLOW_LOOPBACK_TARGETS=true`. Only a debug
  build honors it. A release build logs a warning and ignores it.

### Naming the two hosts

The host comes from the **account**: `create-account --host` and `import-session` record the
PDS, so naming two accounts spans two hosts. `import-session` is standard
`com.atproto.server.createSession` and nothing else, so any account on any atproto PDS can
play either role. Imported accounts are marked `kind: foreign` and are never touched by
`delete-ephemeral`.

### What is still exercised by hand

| Surface | Why |
|---|---|
| client attestation (the positive `allowedApps` case, managedspace policies) | the authority resolves the caller's `client_id` **URL** to fetch its JWKS |
| the alpha `@atproto` TS SDK as a client; the bulletin sample app | ship on atproto's `permissioned-data` branch and move weekly |

The Friday [alpha-watch routine](../../docs/operations/spaces-alpha-watch-routine.md) tracks
the spec drift that would invalidate any of this.

## What the suite checks

| Step | What it proves |
|---|---|
| health / describeServer | deployment up, config sane |
| ensure account | provisioning flow: claim code → mobile account → PDS repo-signing key → client-signed did:plc genesis op → handle → session |
| identity | `resolveHandle`, `/.well-known/atproto-did`, and the plc.directory DID doc all agree; PDS endpoint in the doc points at this deployment |
| CRUD | createRecord → getRecord (CID match) → listRecords → deleteRecord |
| spaces | Atproto Spaces round-trip on the account's own PDS: `space.createSpace` → `space.createRecord` → getRecord/listRecords/listSpaces → `getLatestCommit`/`listRepoOps`/`getRepo` (STAR archive parsed: the commit as metadata, keys in strict order, the record present) → deleteRecord → `deleteSpace` (random skey per run; the space is torn down even on failure) |
| spaces allowedApps | an `allowedApps` space answers `AppNotAuthorized` to an `authorizeSpaceSync` naming no client |
| firehose | a live `subscribeRepos` subscriber sees the `#commit` frame for a write, correct repo + op path |
| sync | CAR export parses, root CID == `getLatestCommit`, `getRepoStatus` active, repo in `listRepos` |
| network | relay (`bsky.network`) crawl status + AppView profile visibility — **informational** (staging may not be crawled); PDS→AppView service-proxy auth leg must pass |
| interact | resolve `@malpercio.dev` (did:web doc + PDS resolveHandle agree) → follow → like latest post → mention post → delete all of it |
| lifecycle | ephemeral account created, verified, deactivated with `deleteAfter`; the server reaper purges it (~5 min) and broadcasts `#account` deleted |

Individual steps are runnable standalone (`verify-identity`, `crud-test`,
`spaces-test`, `spaces-allowlist`, `spaces-interop`, `firehose-test`, `sync-test`,
`network-check`, `interact …`) —
see `just interop help`.

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
