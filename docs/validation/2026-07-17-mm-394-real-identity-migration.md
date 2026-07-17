# MM-394 real-identity migration to production — record

**Status: COMPLETE — custody claimed and outbound migration passed; identity live on
production 2026-07-17 03:05 UTC.** The first **real personal identity**
(`did:plc:j5plnthc7pawnzs35ioujdkk`, handle `on-plc.malpercio.dev`) moved from the
self-hosted reference PDS at `pds.malpercio.dev` to production Custos
(`https://obsign.org`), with the wallet's Secure-Enclave device key claimed into
`rotationKeys[0]` first and the migration op self-signed by it. Both MM-241 pass
conditions recorded below. The run surfaced two blockers (one production deploy bug,
one source-PDS blobstore fault) and two follow-on tickets; all captured here.

This is the sibling record to
[2026-07-07-mm-241-live-migration.md](2026-07-07-mm-241-live-migration.md) — MM-241
validated the flow against bsky.social with a dedicated test account; this run applied
it to a daily-driver identity with a **self-hosted reference PDS as the source**, the
one leg MM-241 never exercised.

- Ticket: [MM-394](https://linear.app/malpercio/issue/MM-394)
- Design: [ADR-0002](../architecture/decisions/0002-wallet-authorized-account-migration.md);
  runbook discipline per MM-241 (both pass conditions recorded per leg)
- Tooling: the Obsign wallet (both legs, on device), `curl` + DNS-over-HTTPS for the
  pre-flight and pass-condition checks

## What this run proved beyond MM-241

| Delta | Result |
|---|---|
| Claim flow against a **self-hosted reference PDS** (MM-241 leg (a) ran against bsky.social only) | Passed — email-tokened `signPlcOperation` on `pds.malpercio.dev` (v0.4.208) inserted the wallet key at `rotationKeys[0]`, services untouched |
| A **real identity** with prior history (4 PLC ops, last 2024-02-28, single source-held secp256k1 rotation key) | Passed — both prior-state reads and the `prev` chain held; no nullifications |
| Production upgrade path on a **populated** database | Failed first (MM-401), fixed, then passed — see "Bugs found" |
| Source-side blob-serving fault mid-migration | Diagnosed externally; migration parked safely and resumed — see "Bugs found" |

## Pre-flight (2026-07-16/17)

- [x] **MM-394 step-1 fixes on production.** Production was on v0.5.0, which predated all
      three named pre-flight fixes (MM-386 DPoP downgrade, MM-387 SSRF, MM-388 updateHandle
      stall). v0.5.1 was cut — its deploy **failed** on migration V047 (MM-401, below);
      v0.5.2 carried the fix and deployed cleanly. `_health` confirmed `0.5.2` before
      proceeding.
- [x] **Handle continuity (step 2).** `_atproto.on-plc.malpercio.dev` TXT =
      `"did=did:plc:j5plnthc7pawnzs35ioujdkk"`, verified via two independent DoH resolvers
      (Cloudflare + Google), so resolution never depended on the source PDS's
      `/.well-known/atproto-did` route surviving decommission.
- [x] Production claim code minted; wallet build from current `main` (carries MM-305/306
      and the MM-389 removal-recovery fix).
- [x] Source-PDS password at hand (MM-302: outbound source login must be a full
      `createSession`; the operator controls the reference PDS's email delivery for the
      claim token).

## Leg 1 — claim custody (source: pds.malpercio.dev)

Wallet "Bring an identity" against the self-hosted reference PDS: password source login,
email-tokened `signPlcOperation`, PDS-signed insertion of the wallet device key.

**PLC op** (`createdAt 2026-07-17T02:52:08.768Z`, cid `bafyreicaja4wzgh4rr3…`, not
nullified):

- `rotationKeys`: `["did:key:zDnaejzHAuNCud5W6ku4sSPUi6s9wbdKkumG7raMf8m6sYbFu",` ← **wallet Secure-Enclave key at [0]**
  `"did:key:zQ3sheFiDeFef2i9HcJXa3op3Q3fi8apTjszKHD6gEJmeJ7Va"]` ← source's original secp256k1 key preserved at [1]
- services / verificationMethods / alsoKnownAs: **unchanged** (claim-only, per the
  phased custody-first design)

Path detector reported `SelfSigned` post-claim. From this point every subsequent state
was recoverable by a wallet-signed corrective op — the run's safety anchor.

## Leg 2 — outbound migration (destination: https://obsign.org)

Wallet outbound flow on device: password source login → deactivated destination account
via service auth → `importRepo` → blob drain → preferences → verify-import → review →
self-signed PLC op → finalize (activate dest, mint sovereign session, deactivate source).

**Attempt 1 failed at the blobs leg** (`BLOB_TRANSFER_FAILED`): the source PDS returned
HTTP 500 `InternalServerError` on **every** `com.atproto.sync.getBlob` for this DID (all
4 blobs — the avatar + 3 post images) while `getRepo`/`listBlobs`/record reads served
fine — blob metadata present, blobstore reads failing server-side. The orchestrator
parked safely: destination account existed deactivated with the repo imported, source
still active and authoritative, phase not advanced (retry-safe by design).
**Resolution:** the blob-referencing content was removed on the source (blobs deemed
unrecoverable; CDN derivatives are re-encoded and can't match the CIDs), and the
migration re-run from the top; the drain emptied and verify-import reconciled.

**PLC op** (`createdAt 2026-07-17T03:05:14.046Z`, cid `bafyreibmj65ijgw56bi…`, not
nullified, **self-signed by the wallet key**):

- `rotationKeys`: `["did:key:zDnaejzHAuNCud5W6ku4sSPUi6s9wbdKkumG7raMf8m6sYbFu",` ← wallet key **unchanged at [0]**
  `"did:key:zDnaeygSwD7deHtwjtJeN9wD3arYMGmAhssjcgpz3BG5HGdWq"]` ← production's recommended key (source's secp256k1 key drops out — expected)
- `services.atproto_pds.endpoint`: `https://obsign.org`
- `verificationMethods.atproto`: production's recommended signing key
- `alsoKnownAs`: `["at://on-plc.malpercio.dev"]` — handle preserved

## Pass conditions (recorded 2026-07-17 ~03:15 UTC)

**1. plc.directory audit entry** — verified above for both legs: 6 ops total, none
nullified; wallet key at `rotationKeys[0]` through both new ops; endpoint → production.

**2. Handle / DID / repo resolution against production:**

```
GET https://obsign.org/xrpc/com.atproto.identity.resolveHandle?handle=on-plc.malpercio.dev
→ {"did":"did:plc:j5plnthc7pawnzs35ioujdkk"}

GET https://plc.directory/did:plc:j5plnthc7pawnzs35ioujdkk
→ service #atproto_pds endpoint = https://obsign.org

GET https://obsign.org/xrpc/com.atproto.sync.getRepoStatus?did=…
→ {"active": true, "rev": "3mqsrbvi3a22z"}

GET https://obsign.org/xrpc/com.atproto.sync.getLatestCommit?did=…
→ {"cid": "bafyreiccgdgel36lndvfbolszjjqzjkkfgub6tq4agvz4opr2jm4oxa5ga", "rev": "3mqsrbvi3a22z"}

GET https://pds.malpercio.dev/xrpc/com.atproto.sync.getRepoStatus?did=…
→ {"active": false, "status": "deactivated"}   ← clean handoff, source retired
```

## Bugs found and follow-ons

| Issue | Found by | Disposition |
|---|---|---|
| **MM-401** — production deploy of v0.5.1 failed: migration V047 rebuilt `agent_identities` without stashing `agent_audit_events` (V040 FK child), tripping a FOREIGN KEY failure on any DB with recorded agent activity — i.e. production and nowhere else (fresh test DBs have no audit events). Migration transaction rolled back atomically; production stayed intact on v0.5.0/schema v46 | pre-flight release | Fixed (PR #303: stash + rowid-preserving refill + populated-upgrade-path regression test + rebuild-invariant doc in `db/AGENTS.md`); shipped in v0.5.2 |
| **Source blobstore fault** — `pds.malpercio.dev` (reference PDS v0.4.208) 500s on every `getBlob` for this DID; metadata present, file reads failing. Not a Custos or wallet defect | blobs leg, attempt 1 | Operator removed the referencing content on the source; blobs unrecoverable (CDN keeps only re-encoded derivatives). Re-run passed |
| **Wallet UX gap** — `MigrationError::BlobTransferFailed` carries the failing CID and which half failed (fetch-from-source vs upload-to-destination), but `MigrationProgressScreen.describeError` drops it for the generic "Couldn't transfer one or more blobs." | blobs-leg diagnosis | Noted in MM-394 comments; small fix, unticketed as of this record |
| **MM-402** — the official Bluesky app does password `createSession` against third-party PDSes (no OAuth), so a passwordless sovereign account can't sign in to the flagship client. Server side already exists (V031 app-password fallback in `createSession`, scope-bounded `com.atproto.appPass`); what's missing is the wallet mint/list/revoke surface | post-migration daily-driver check | Filed — the remaining daily-driver gap for this identity |

## Post-run state

- Identity live on production: handle resolves, repo serves, sovereign custody intact
  (wallet key at `rotationKeys[0]`, sixth op, zero nullifications across the identity's
  history).
- Source account on `pds.malpercio.dev`: deactivated at handoff; the host can now be
  decommissioned without breaking handle resolution (DNS TXT is authoritative).
- Open follow-ons: MM-402 (Bluesky app login), sovereign passwordless login check
  (MM-306 flow) and any handle change (MM-305) remain exercisable at leisure — custody
  makes them non-urgent.
