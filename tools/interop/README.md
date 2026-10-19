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

`just interop-test` unit-checks the pure pieces offline (DPoP proof construction, CAR
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

## Atproto Spaces

Three commands, in order of how much of the protocol they touch:

```sh
just interop spaces-test --name primary          # authority = self, one host
just interop spaces-cross-host --member primary  # + delegation → DPoP credential → credential-authed reads
just interop spaces-allowlist --name primary     # allowList refuses an unattested credential request
```

`spaces-test` is the single-host round-trip: `simplespace.createSpace` → `space.createRecord`
→ get/list/listSpaces → `getLatestCommit`/`listRepoOps`/`getRepo` → teardown. It reads the
space export as a **parsed** CAR, not a byte count: two roots in order (signed commit, then
the DRISL record index), every block verified against the CID naming it, and the written
record present in the index and carried as a block.

`spaces-cross-host` drives the credential flow a foreign implementation actually judges a
host on:

1. the member writes into the space through **their own PDS** (the repo host) — which
   registers a space it may never have heard of, the path that lets anyone join a foreign
   authority's space;
2. the repo host mints a **delegation token** (`space.getDelegationToken`);
3. the **space host** spends it for a DPoP-bound **space credential**
   (`space.getSpaceCredential`, Bearer delegation + a mint-time proof carrying no `ath`);
4. that credential drives reads on **both** hosts — `space.getRecord`/`listRepoOps`/`getRepo`
   on the repo host, `simplespace.getSpace`/`space.listRepos` on the authority — each under
   `Authorization: DPoP` with a fresh per-request proof;
5. it also asserts the credential is **refused** when presented without a proof. A host that
   accepts it as a plain bearer token has thrown away the binding.

### Naming the two hosts

The host comes from the **account**, not from a global — `import-session` records the PDS it
authenticated against, so naming two accounts spans two hosts:

```sh
# adopt an account on a foreign alpha PDS (standard createSession; no Custos /v1/* provisioning)
just interop import-session --name alpha --host https://pds.spaces-alpha.bsky.network \
  --identifier alice.example --password '…'

# Custos repo host + foreign space host
just interop spaces-cross-host --member primary --authority alpha

# the reverse: foreign repo host + Custos space host
just interop spaces-cross-host --member alpha --authority primary
```

With only `--member`, both halves are that account's PDS. That degenerate run still exercises
the entire credential path, so `suite` includes it and the flow is covered without a second
deployment.

To join a space that already exists somewhere (e.g. a bulletin space), pass it directly —
the authority's host is then resolved from its **DID document** the way a real client would,
preferring an `#atproto_space` / `AtprotoSpaceHost` service entry and falling back to the
PDS endpoint. `--space-host` overrides that when the authority publishes neither:

```sh
just interop spaces-cross-host --member primary \
  --space at://did:plc:…/space/my.bulletin.board/self [--space-host https://…]
```

### Bring your own session

`create-account` drives the Custos-proprietary `/v1/*` provisioning ceremony and cannot
reach a foreign PDS. `import-session` is the documented alternative: it does nothing but
standard `com.atproto.server.createSession` and records the result (with its host) in
`.state/state.json`. That is all the spaces scenarios need, so any account on any
atproto PDS can play either role. Imported accounts are marked `kind: foreign` and are
never touched by `delete-ephemeral`.

### What is still exercised by hand

Three parts of the alpha surface need a **publicly reachable host** the CLI does not have,
and so stay manual:

| Surface | Why it needs a host |
|---|---|
| client attestation (the positive `allowList` case, managing-app policies) | the authority resolves the caller's `client_id` **URL** to fetch its JWKS |
| `registerNotify` → receive `notifyWrite` (acting as a syncer) | the space host POSTs to the syncer's endpoint |
| the alpha `@atproto` TS SDK as a client; the bulletin sample app | ship on atproto's `permissioned-data` branch and move weekly |

`spaces-allowlist` covers the reachable half of the app perimeter: an `allowList` space
must answer `AppNotAuthorized` (403) to a credential request naming no client — including
the authority's own request, which is the part a host is likeliest to get wrong. The Friday
[alpha-watch routine](../../docs/operations/spaces-alpha-watch-routine.md) tracks the spec
drift that would invalidate any of this.

**Gotcha:** the mint-time DPoP proof's `htu` is checked against the authority's *configured
public URL*. Calling a host by an address it does not publish for itself fails with a
generic `InvalidToken`; the CLI adds a hint on 401, but the fix is always to use the URL
the host publishes.

## What the suite checks

| Step | What it proves |
|---|---|
| health / describeServer | deployment up, config sane |
| ensure account | provisioning flow: claim code → mobile account → PDS repo-signing key → client-signed did:plc genesis op → handle → session |
| identity | `resolveHandle`, `/.well-known/atproto-did`, and the plc.directory DID doc all agree; PDS endpoint in the doc points at this deployment |
| CRUD | createRecord → getRecord (CID match) → listRecords → deleteRecord |
| spaces | Atproto Spaces round-trip on the account's own PDS: `simplespace.createSpace` → `space.createRecord` → getRecord/listRecords/listSpaces → `getLatestCommit`/`listRepoOps`/`getRepo` (CAR parsed: two roots, blocks verified against their CIDs, record present in the index) → deleteRecord → `deleteSpace` (random skey per run; the space is torn down even on failure) |
| spaces credential | delegation token → DPoP-bound space credential → credential-authed reads on both the repo host and the authority; the credential is rejected when presented without a proof |
| spaces allowList | an `allowList` space answers `AppNotAuthorized` to a credential request naming no client |
| firehose | a live `subscribeRepos` subscriber sees the `#commit` frame for a write, correct repo + op path |
| sync | CAR export parses, root CID == `getLatestCommit`, `getRepoStatus` active, repo in `listRepos` |
| network | relay (`bsky.network`) crawl status + AppView profile visibility — **informational** (staging may not be crawled); PDS→AppView service-proxy auth leg must pass |
| interact | resolve `@malpercio.dev` (did:web doc + PDS resolveHandle agree) → follow → like latest post → mention post → delete all of it |
| lifecycle | ephemeral account created, verified, deactivated with `deleteAfter`; the server reaper purges it (~5 min) and broadcasts `#account` deleted |

Individual steps are runnable standalone (`verify-identity`, `crud-test`,
`spaces-test`, `spaces-cross-host`, `spaces-allowlist`, `firehose-test`, `sync-test`,
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
