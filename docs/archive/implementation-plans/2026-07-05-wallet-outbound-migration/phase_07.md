# Wallet Outbound Migration — Phase 7: Interop CLI migrate command

**Goal:** Make the full self-signed outbound migration runnable end-to-end against live infrastructure via the interop CLI — a `migrate.js` module (`performMigration` + `verifyMigration`) and a `migrate` command group (`perform`, `verify`) that self-signs the PLC op with the rotation key already in `.state/state.json`, gated on an explicit `--target-pds` and excluded from the default `suite`.

**Architecture:** Independent of the Rust work — this is a second, from-scratch implementation of the same migration sequence using the interop CLI's raw-XRPC-over-Bearer idiom (no DPoP, no `@atproto/api`). It reuses the existing `account.js` session helpers, `identity.js`/`sync.js` resolvers, and the `crypto.js` DAG-CBOR + P-256 signing pattern (the same one that signs genesis ops), so it can self-sign the DID-repointing PLC operation with the account's stored rotation key.

**Tech Stack:** Node.js (ESM, Node 22), raw `fetch`-based XRPC (`http.js`/`xrpc`), `@atproto/crypto` (`P256Keypair`), `@ipld/dag-cbor`, existing interop modules.

**Scope:** Phase 7 of 7. **Infrastructure/integration phase** — verified operationally (run against a second instance), not by unit tests. The interop tool has no unit-test harness.

**Codebase verified:** 2026-07-05.

---

## Acceptance Criteria Coverage

This phase implements and tests:

### wallet-outbound-migration.AC9: The interop CLI can drive the migration end-to-end
- **wallet-outbound-migration.AC9.1 Success:** `migrate perform --name <n> --target-pds <url>` drives the seven-step flow against a live source→destination pair, self-signing the PLC op with the rotation key in `.state/state.json`.
- **wallet-outbound-migration.AC9.2 Success:** `migrate verify --name <n> --target-pds <url>` confirms the handle, DID, and repo resolve to the new PDS after migration.
- **wallet-outbound-migration.AC9.3 Edge:** The `migrate` command is not part of the default single-PDS `suite` run and requires an explicit `--target-pds`.

---

## Verified codebase facts

- `tools/interop/src/cli.js`: `main()` reads `const [command, ...rest] = process.argv.slice(2)`; subcommand `const sub = rest[0] && !rest[0].startsWith('--') ? rest[0] : undefined`; `const v = flags(rest)`. `flags(args, extra={})` uses `node:util` `parseArgs` with an options map (`name`, `handle`, `claim-code`, booleans…) — add new flags via the `options` map. Output: `const print = (data) => console.log(JSON.stringify(data, null, 2))`. Command-group example (`interact`) switches on `sub` with a `default: throw new Error('unknown ... subcommand')`. `requireName(v)` enforces `--name`.
- `tools/interop/src/account.js`: `ensureSession(name)` returns `{ ...account, accessJwt }`, refreshing via `com.atproto.server.refreshSession` (`token: account.refreshJwt`) or re-`createSession` as needed. Authed calls: `xrpc(BASE_URL, 'method', { token: account.accessJwt, method, body, params })`. `persist(fields)` merges into `state.accounts[name]` and `saveState`.
- `.state/state.json` per account: `handle, email, password, did, accessJwt, refreshJwt, rotationKeyId, rotationKeyPrivateHex (hex P-256 scalar), repoSigningKeyId, deviceKeyId, ...`.
- `tools/interop/src/crypto.js`: `keypairFromHex(privateKeyHex) -> P256Keypair.import(hex, { exportable: true })`; `buildGenesisOp({ rotationKeyId, repoSigningKeyId, rotationKeypair, handle, pdsUrl })` builds `{ prev:null, type:'plc_operation', services:{atproto_pds:{type,endpoint}}, alsoKnownAs:[at://handle], rotationKeys:[...], verificationMethods:{atproto} }`, signs `dagCbor.encode(unsignedOp)` with `rotationKeypair.sign`, appends `sig: base64url`, and derives the did from `sha256(dagCbor.encode(signedOp))`.
- `tools/interop/src/identity.js`: `resolveHandleViaPds(handle)`, `resolveHandleViaWellKnown(handle)`, `fetchPlcDocument(did)` (`GET {PLC_URL}/{did}`), `pdsEndpointFromDoc(doc)` (finds `#atproto_pds` serviceEndpoint).
- `tools/interop/src/sync.js`: `getRepoCar(did)` (`GET {BASE_URL}/xrpc/com.atproto.sync.getRepo?did=...`, raw bytes). **It targets `BASE_URL`** — for verify, fetch from `targetPds` instead (pass a base or add a variant).
- Run: `just interop <args>` (wrapper `bin/interop`), `just interop-setup`. Default `suite` command runs the single-PDS end-to-end and must NOT include migration.
- `tools/interop/README.md` sections: Ground rules → Setup → Quick start → What the suite checks → State & credentials → Cleanup. Add "Migration testing" after Quick start.

## PLC-op self-signing for migration (the one novel bit)

The migration op is a **non-genesis** `plc_operation` with `prev` = the CID of the account's most recent PLC op (not `null`). Build it like `buildGenesisOp` but:
- `prev`: fetch the account's op log and take the last op's CID. Use `GET {PLC_URL}/{did}/log/audit` → array of entries each with a `cid`; `prev = entries.at(-1).cid`. (Confirm the audit-log entry shape exposes `cid`; the interop's `fetchPlcDocument` doesn't return it, so read the audit log.)
- `services.atproto_pds.endpoint = targetPds` (the repointing).
- `verificationMethods.atproto = <reserved signing key from destination>` — obtained from the destination's `getRecommendedDidCredentials` (or the `reserveSigningKey` response).
- `rotationKeys`, `alsoKnownAs` = preserved (use the destination's `getRecommendedDidCredentials` recommendation, which keeps the wallet rotation key authorized).
- Sign `dagCbor.encode(unsignedOp)` with `keypairFromHex(account.rotationKeyPrivateHex)`, append `sig: base64url`, POST the signed op to `{PLC_URL}/{did}`.

This is the same signing primitive as `buildGenesisOp`; factor a shared `signPlcOp(unsignedOp, rotationKeypair)` helper in `crypto.js` if it reduces duplication.

---

<!-- START_TASK_1 -->
### Task 1: `migrate.js` — `performMigration`

**Verifies:** wallet-outbound-migration.AC9.1

**Files:**
- Create: `tools/interop/src/migrate.js`
- Modify (optional): `tools/interop/src/crypto.js` (extract a shared `signPlcOp`/`buildMigrationOp`)

**Implementation:** `export async function performMigration({ name, targetPds })` driving the sequence with raw XRPC:
1. Load the source account (`ensureSession(name)` → source `accessJwt`, plus `did`, `handle`, `email`, `rotationKeyPrivateHex`).
2. `describeServer(targetPds)` → `destDid` (`GET {targetPds}/xrpc/com.atproto.server.describeServer`).
3. `reserveSigningKey`: `POST {targetPds}/xrpc/com.atproto.server.reserveSigningKey` body `{ did }` → `{ signingKey }` (auth: none, idempotent).
4. `getServiceAuth` on the **source**: `xrpc(BASE_URL, 'com.atproto.server.getServiceAuth', { token: source.accessJwt, params: { aud: destDid, lxm: 'com.atproto.server.createAccount' } })` → `{ token }`.
5. `createAccount` (migration) on **targetPds** with the service-auth token as Bearer: `POST {targetPds}/xrpc/com.atproto.server.createAccount` header `Authorization: Bearer {serviceAuthToken}`, body `{ handle, email, did, inviteCode? }` → `{ accessJwt, refreshJwt }` (the **destination** session). Tolerate a 409 `DidAlreadyExists` if re-running (log + continue, re-`createSession` on the dest if a password was set, or reuse a stored dest session).
6. Repo: `getRepoCar(did)` from source (bytes) → `POST {targetPds}/xrpc/com.atproto.repo.importRepo` header `Content-Type: application/vnd.ipld.car` + dest Bearer, body the CAR bytes.
7. Blobs: loop `POST/GET {targetPds}/xrpc/com.atproto.repo.listMissingBlobs?cursor=...` (dest Bearer) → for each `{cid}` `GET {BASE_URL}/xrpc/com.atproto.sync.getBlob?did=&cid=` (source, no auth) → `POST {targetPds}/xrpc/com.atproto.repo.uploadBlob` (dest Bearer, raw bytes) until a page returns no blobs.
8. Preferences: `getPreferences` (source, Bearer) → `putPreferences` (dest, Bearer).
9. `checkAccountStatus` (dest) → assert `importedBlobs === expectedBlobs` and `repoCommit` present.
10. Identity op: `getRecommendedDidCredentials` (dest) → build the migration `plc_operation` (`prev` from the audit log, `services.atproto_pds.endpoint = targetPds`, `verificationMethods.atproto = signingKey`, preserved `rotationKeys`/`alsoKnownAs`), sign with `keypairFromHex(account.rotationKeyPrivateHex)`, `POST {PLC_URL}/{did}` the signed op.
11. `activateAccount` (dest, Bearer) — retry a few times if the DID doc hasn't propagated (poll `checkAccountStatus.validDid`), then `deactivateAccount` (source, Bearer).
12. `persist({ pds: targetPds, accessJwt: destAccessJwt, refreshJwt: destRefreshJwt, migrationStatus: 'complete' })` so `verify` and later interop steps target the new PDS.

Use small `xrpc`-style helpers that accept an explicit base URL and a Bearer token (the existing `xrpc` takes `BASE_URL` first; pass `targetPds` for destination calls). Respect the interop's rate-limit/pacing conventions (`request` helper).

**Verification (operational, needs a second instance):**
```
just interop create-account --name mtest
just interop migrate perform --name mtest --target-pds <dest-url>
```
Expected: prints a JSON summary; the destination serves the repo and the DID's `atproto_pds` now points at `<dest-url>`. Without a second instance, at minimum `node --check tools/interop/src/migrate.js` passes and the CLI wiring (Task 3) works.

**Commit:** `feat(interop): performMigration self-signed outbound migration`
<!-- END_TASK_1 -->

<!-- START_TASK_2 -->
### Task 2: `migrate.js` — `verifyMigration`

**Verifies:** wallet-outbound-migration.AC9.2

**Files:**
- Modify: `tools/interop/src/migrate.js`

**Implementation:** `export async function verifyMigration({ name, targetPds })` that, reusing `identity.js`/`sync.js`:
- Resolves the account's `handle` → `did` (`resolveHandleViaPds` / `resolveHandleViaWellKnown`) and asserts the `did` is unchanged from `.state/state.json`.
- `fetchPlcDocument(did)` → `pdsEndpointFromDoc(doc)` and asserts it equals `targetPds` (the DID now points at the new PDS).
- Fetches the repo from `targetPds` (`GET {targetPds}/xrpc/com.atproto.sync.getRepo?did=...`) and asserts a non-empty CAR (repo serveable on the new PDS). `sync.js`'s `getRepoCar` targets `BASE_URL`; either add a `baseUrl` param or inline the fetch against `targetPds`.
- Returns a structured result `{ did, handle, pds, ok }` for `print`.

**Verification (operational):**
```
just interop migrate verify --name mtest --target-pds <dest-url>
```
Expected: `{ ok: true, pds: "<dest-url>", ... }` — handle/DID/repo resolve to the new PDS.

**Commit:** `feat(interop): verifyMigration resolves identity to new PDS`
<!-- END_TASK_2 -->

<!-- START_TASK_3 -->
### Task 3: `cli.js` `migrate` command group + README

**Verifies:** wallet-outbound-migration.AC9.3

**Files:**
- Modify: `tools/interop/src/cli.js`
- Modify: `tools/interop/README.md`

**Implementation:**
- Add `target-pds: { type: 'string' }` (and `invite-code` if needed) to the `flags` options map.
- Add a `case 'migrate':` in `main()`'s switch, following the `interact` group pattern:
  ```js
  case 'migrate': {
    const targetPds = v['target-pds'];
    if (!targetPds) throw new Error('migrate requires --target-pds <url> (needs a second PDS instance; not part of `suite`)');
    switch (sub) {
      case 'perform': print(await performMigration({ name: requireName(v), targetPds })); break;
      case 'verify':  print(await verifyMigration({ name: requireName(v), targetPds })); break;
      default: throw new Error(`unknown migrate subcommand "${sub}" (perform|verify)`);
    }
    break;
  }
  ```
- Import `performMigration`/`verifyMigration` at the top of `cli.js`.
- **Do NOT** add `migrate` to `suite.js` / the `suite` command (AC9.3 — it targets a second instance).
- README: add a "Migration testing" subsection after "Quick start" documenting: needs a second PDS instance, `--target-pds <url>` is required, the two subcommands (`perform`, `verify`), and that it is intentionally excluded from the default `suite`.

**Verification:**
```
node --check tools/interop/src/cli.js
node --check tools/interop/src/migrate.js
just interop migrate perform --name x            # must error: requires --target-pds  (AC9.3)
```
Expected: syntax OK; the no-`--target-pds` invocation errors clearly. Full `perform`/`verify` need a second instance.

**Commit:** `feat(interop): migrate command group (perform|verify) + README`
<!-- END_TASK_3 -->

---

## Phase 7 done when

- `tools/interop/src/migrate.js` exports `performMigration` (seven-step self-signed flow) and `verifyMigration` (handle/DID/repo resolve to the new PDS).
- `cli.js` has a `migrate` group (`perform`, `verify`) gated on `--target-pds`, excluded from `suite` (AC9.3).
- README documents the migration subsection.
- `node --check` passes for both files; the `--target-pds`-missing invocation errors; a full run against a second instance completes `perform` then `verify` (AC9.1/AC9.2) when infrastructure is available.
- Covers wallet-outbound-migration.AC9.1–AC9.3.
