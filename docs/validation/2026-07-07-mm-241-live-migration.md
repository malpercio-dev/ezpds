# MM-241 live migration round trip — runbook + record

**Status: LEGS (a), (r), (b), AND (c) EXECUTED (all pass — see the execution record);
leg (d) pending, hard-blocked by MM-310** (staging cached this DID's document as leg (b)'s
destination, and `resolve_did_document` is cache-first with no refresh — leg (d)'s inbound
`createAccount` on staging would deterministically reject production's service token
against the fossil doc; land MM-310 + staging deploy first). Leg (r) flushed out and
validated fixes for five defects (MM-295/297/298/299 server-side, MM-300 wallet-side)
before any leg touched the real identity; legs (b)/(c) flushed out three more
(MM-301/302 wallet-side, MM-304 server-side).
This document is both the checklist for the live bsky.social migration round trip and, after
execution, the permanent record of the run. A human operator executes or supervises every
leg: the run touches the real plc.directory, the real bsky.social, and permanent `did:plc`
state.

- Ticket: [MM-241](https://linear.app/malpercio/issue/MM-241) (the canonical MM-207 e2e; the
  one unvalidated leg of the migration epic)
- Design: [ADR-0002](../architecture/decisions/0002-wallet-authorized-account-migration.md),
  design plan [v0.1 operational proof](../archive/design-plans/2026-07-07-v01-operational-proof.md)
  (op-proof.AC4)
- Tooling: the Obsign wallet (all legs), `curl` + `jq` for the plc.directory audit and
  resolution checks. The interop CLI's `migrate perform`/`migrate verify`
  ([`tools/interop`](../../tools/interop/README.md)) is the **fallback driver only** — see
  "Fallback: interop-driven variant" at the end.

## Revision note (2026-07-11)

The original runbook assumed leg (a) was a full inbound migration (repoint to staging +
deactivate on bsky) and drove legs (b)/(c) with the interop CLI against an interop-managed
identity. Leg (a) as shipped is **claim-only** (the phased custody-first design): the wallet
key was inserted at `rotationKeys[0]` and the account stayed on bsky.social. Consequently
the identity's rotation key lives in the phone's Secure Enclave, not in
`tools/interop/.state/state.json`, and the remaining legs are **wallet-driven end to end**.
This is a *stronger* proof than the original plan: every hop's PLC op is self-signed by the
Secure-Enclave-held key via the wallet's outbound-migration flow — the source PDS never
signs, and no email token is needed after leg (a).

## The round trip

| Leg | From → To | Driver | What it proves |
|---|---|---|---|
| (a) Claim | custody: bsky.social PDS → wallet | Obsign wallet claim flow ("Bring an identity") | **DONE 2026-07-11.** PDS-signed insertion path: bsky.social's email-tokened `signPlcOperation` inserted the wallet's device key as `rotationKeys[0]` |
| (r) Rehearsal *(optional but recommended)* | staging → production, **throwaway identity** | Obsign wallet in the iOS simulator | The full outbound orchestrator (service auth, claim-code account creation, repo/blob/prefs transfer, review guard, self-signed op, activate/deactivate) with zero risk to the real identity |
| (b) Outbound | bsky.social → ezpds staging | Obsign wallet outbound flow, on device | **The differentiator**: the Secure-Enclave rotation key self-signs the PLC op; bsky.social never signs and cannot veto |
| (c) Hop | ezpds staging → ezpds production | Obsign wallet outbound flow, on device | Custos→Custos migration; custody unchanged across a second hop |
| (d) Return | ezpds production → ezpds staging | Obsign wallet outbound flow, on device | Round-trip closure; nothing about the identity degraded |

Deployments: staging `https://ezpds-staging.up.railway.app`, production
`https://obsign.org`.

## Required pass conditions — checked after EVERY leg

A leg is **not passed** because "the flow completed". Both checks below must be recorded per
leg (these are MM-241's acceptance criteria):

**1. plc.directory audit log shows the correct new entry for the hop.**

```sh
DID="did:plc:u7j7xdhvkwx3xlf6xjkbpdn7"   # the migrating identity
curl -s "https://plc.directory/$DID/log/audit" | jq '.[-1] | {createdAt, nullified, operation: {rotationKeys: .operation.rotationKeys, pds: .operation.services.atproto_pds.endpoint}}'
```

Expected per leg (`WALLET_KEY` = `did:key:zDnaevBrDyAkZPmxv9v7cG7zTXmdqasuf12vuh5zRbMrUeQk3`):
- after (a): **recorded — see execution record.** `rotationKeys[0]` = `WALLET_KEY`; services
  unchanged (claim-only); entry not nullified.
- after (b): `atproto_pds.endpoint` = staging URL; `rotationKeys[0]` still = `WALLET_KEY`
  (the op was **self-signed by it** — bsky's old `zQ3…` keys are replaced by
  `WALLET_KEY` + staging's recommended keys); not nullified.
- after (c): `atproto_pds.endpoint` = production URL; `rotationKeys[0]` still = `WALLET_KEY`.
- after (d): `atproto_pds.endpoint` = staging URL; `rotationKeys[0]` still = `WALLET_KEY`.

**2. Handle, DID document, and repo all resolve correctly against the new host.**

```sh
HANDLE="<the account handle>"
NEW_PDS="https://ezpds-staging.up.railway.app"   # the leg's destination

# Handle → DID (on the new host)
curl -s "$NEW_PDS/xrpc/com.atproto.identity.resolveHandle?handle=$HANDLE" | jq .

# DID document points at the new host
curl -s "https://plc.directory/$DID" | jq '.service[] | select(.id=="#atproto_pds").serviceEndpoint'

# Repo serveable from the new host
curl -s "$NEW_PDS/xrpc/com.atproto.sync.getLatestCommit?did=$DID" | jq .
```

The interop CLI's `migrate verify` does **not** apply to the wallet-custody identity (it is
not interop-managed) — use the raw curls above.

**If a leg fails:** record the failure below, file a bug (its own Linear issue, linked to
MM-241), and **stop the run**. Do not paper over a failed check to reach the next leg.
Expect this: the outbound flow has never run against real bsky.social, and leg (a) needed
six fixes to survive first contact (see execution record).

## Preconditions

- [ ] Both ezpds deployments healthy:
      `curl -s https://ezpds-staging.up.railway.app/xrpc/_health` and the production
      equivalent return 200. Staging sleeps when idle — hit it once and wait for wake.
- [ ] Wallet build ≥ `c7373fc3` (carries the six leg-(a) fixes: MM-288/289/290/291/293/294)
      installed **on the physical device** — legs (b)–(d) must run on the phone, because the
      self-signing key is its Secure Enclave key. The simulator is only valid for leg (r).
- [ ] Leg (a) complete: `WALLET_KEY` at `rotationKeys[0]` of the migrating DID (verify with
      the audit-log curl above). The wallet's path detector must report `SelfSigned` — if it
      routes to `Interop`, stop; custody is not what you think it is.
- [ ] **Claim codes minted for every destination** — staging for legs (r-source is created
      fresh)/(b)/(d), production for legs (r)/(c). Mint via the admin token
      (`EZPDS_ADMIN_TOKEN`) or the Brass Console app. Codes are single-use: legs (b) and (d)
      both target staging and need one each.
- [ ] The bsky.social test account credentials at hand (leg (b)'s source OAuth login).
      No email token is needed for legs (b)–(d) — the identity leg is self-signed.
- [ ] Optional but recommended for shakeout speed: Xcode cable-deploy of dev builds to the
      phone set up, so a bsky-seam fix doesn't cost a full TestFlight cycle.
- [ ] Time budgeted: plc.directory writes are permanent; there is no dry-run mode.

## Rollback notes for the live account

There is no "undo" for a PLC op — rollback means **executing the reverse migration**, which
is exactly what leg (d) rehearses. The custody-first design is itself the safety net: the
wallet holds `rotationKeys[0]`, so whatever state a failed leg leaves behind, the wallet can
always self-sign a corrective op (repoint back to the last-good PDS).

- Failure **before** the PLC op submits (during transfer): the source account is still
  authoritative and untouched. Deactivate the half-created destination account
  (`deactivateAccount` on the target), fix, retry. The orchestrator's migration state is
  in-memory only — an app kill restarts from `prepare_migration`, and its early steps are
  idempotent from the network's point of view (fresh service auth, re-create-or-reuse
  deactivated account).
- Failure **after** the PLC op but before finalize (activate/deactivate): the DID already
  points at the destination. Complete activation manually (`activateAccount` on the
  destination with the wallet's session) rather than rolling back.
- The bsky.social account after leg (b): deactivated, but its data remains exportable for
  30+ days per Bluesky policy; nothing here deletes it.
- Worst case (phone lost mid-run): recovery follows the wallet's recovery-share flow; the
  DID remains resolvable throughout.

## Leg (r) — optional rehearsal: staging → production, throwaway identity, simulator

Purpose: exercise the entire outbound orchestrator once with zero permanent-state risk to
the real identity, so leg (b)'s only untested delta is bsky.social-as-source. The throwaway
DID created here is permanent in plc.directory — that is acceptable; it is disposable by
design.

1. In the simulator (`just ios-dev`): run the **create flow** against staging (claim code
   required). This mints a fresh DID whose `rotationKeys[0]` is the *simulator's* software
   device key — fine here, because this identity never matters.
2. Start the outbound flow ("Move to a new server" / MigrationStartScreen) for that
   identity; destination = `https://obsign.org`, with a production claim code.
3. Run it end to end: source OAuth (against staging), destination account creation,
   repo/blob/preferences transfer, verify-import, review screen (**check: proposed
   `rotationKeys` keep the device key at [0], `atproto_pds` repoints to production**),
   submit, finalize.
4. Record both pass conditions for the throwaway DID. Optionally migrate it back or abandon
   it (deactivated) — either way, note its DID in the record.

## Leg (b) — outbound self-signed: bsky.social → ezpds staging (on device)

1. On the phone, in the wallet: open the claimed identity and start the outbound migration
   flow. Destination PDS = `https://ezpds-staging.up.railway.app`; supply the account email
   and a staging claim code.
2. Source login: OAuth against bsky.social (ASWebAuthenticationSession). This grants
   `transition:generic` — sufficient by design, because the identity leg is self-signed.
   **Watch this seam**: `getServiceAuth`, preferences export, and `deactivateAccount` under
   that scope have never been exercised against real bsky.social.
3. The orchestrator runs: deactivated account on staging → `importRepo` → blob drain →
   preferences → verify-import.
4. Review screen — confirm before submitting: `rotationKeys[0]` = `WALLET_KEY` (unchanged),
   remaining keys = staging's recommended keys (bsky's `zQ3…` keys drop out — expected),
   `atproto_pds` repoints to staging, handle preserved. Biometric gate, submit.
5. Finalize: activate on staging, deactivate on bsky.social.
6. **Record both pass conditions.**

## Leg (c) — hop: staging → production (on device)

Same flow; source is now staging (Custos OAuth — full scopes, our server), destination
`https://obsign.org` with a production claim code. Review expectations: `rotationKeys[0]`
unchanged, keys = `WALLET_KEY` + production's recommended keys, endpoint → production.
**Record both pass conditions.**

## Leg (d) — return: production → staging (on device)

Same flow in reverse; destination `https://ezpds-staging.up.railway.app` with a second
staging claim code. **Record both pass conditions.** This closes the round trip and doubles
as the live proof of the rollback procedure.

## Post-run

- [ ] Steady-state sanity on staging with the migrated-back account: sign in / repo reads
      work; `getLatestCommit` serves; handle resolves.
- [ ] `just interop suite --no-interact` against staging still passes (server-level sanity —
      uses its own interop-managed accounts, not the migrated identity).
- [ ] MM-241: closed with a link to this document, **or** a blocking bug filed and linked.

## Fallback: interop-driven variant

If the wallet outbound flow is blocked by a bug mid-run and the run must continue, the
original interop-CLI variant still exists: `just interop create-account --name primary`
against staging mints a **separate interop-managed identity** (rotation key in
`tools/interop/.state/state.json` — back it up first; treat like a key file), then
`just interop migrate perform/verify --name primary --target-pds <dest>` drives
staging → production → staging. This proves the self-signed op with an interop-held key
rather than the Secure-Enclave key — weaker, but it keeps MM-241's (b)/(c) semantics.
Record which driver was used per leg.

## Execution record

> Fill in during the run. A leg without both recorded checks is not passed.

| Leg | Date (UTC) | Operator | Driver | Audit-log check | Resolution check | Result | Artifacts |
|---|---|---|---|---|---|---|---|
| (a) claim (custody handoff) | 2026-07-11 23:46 | mal | wallet (Obsign TestFlight build from `c7373fc3`, on device) | ✅ newest op `createdAt` 2026-07-11T23:46:15.234Z, not nullified; `rotationKeys[0]` = wallet key `did:key:zDnaevBrDyAkZPmxv9v7cG7zTXmdqasuf12vuh5zRbMrUeQk3`; both prior bsky `zQ3…` keys preserved in original order; services unchanged | ✅ `resolveHandle` → DID; `describeRepo` on fibercap PDS `handleIsCorrect: true`; AppView `getProfile` intact | ☑ pass | audit-log + resolution curl outputs in session transcript |
| (r) rehearsal (throwaway, sim) | 2026-07-12 13:56 | mal | wallet (simulator; staging v0.4.4-train source → production v0.4.4 dest) | ✅ newest op `createdAt` 2026-07-12T13:56:58.379Z, not nullified; **self-signed**; `rotationKeys[0]` = sim device key `did:key:zDnaechUQpzVqd51Cvv5oJ1CwArPLXq6zYbWMGw1dmKLGkAni`, [1] = production's recommended key; `atproto_pds` → `https://obsign.org` | ✅ repo serves from production (`getLatestCommit` rev `3mqhdcysv6e22`); staging reports `deactivated` at the same rev (clean handoff, no fork); handle resolves on production | ☑ pass | throwaway DID: `did:plc:ufko7jay3hdaxxsryhqwacpi` (`maltest456.ezpds-staging.up.railway.app`); abandoned active on production. Curl outputs in session transcript |
| (b) outbound self-signed | 2026-07-12 19:08 | mal | wallet (TestFlight build from PR #205 merge, on device; source bsky.social, dest staging v0.4.5+MM-304) | ✅ newest op `createdAt` 2026-07-12T19:08:52.762Z, not nullified; **self-signed**; `rotationKeys[0]` = `WALLET_KEY`, [1] = staging's recommended key `did:key:zDnaeUWgDx6kAswki3VyjN42SDNTYBobX4hjR1tf4qn6AeYb3` (bsky's `zQ3…` keys replaced); `atproto_pds` → `https://ezpds-staging.up.railway.app` | ✅ staging `getRepoStatus` `active: true` rev `3mqdcm57v4u22`; bsky auth-gates the repo's sync endpoints post-deactivation (no clean public probe); handle unchanged in `alsoKnownAs` (dangling by design — bsky no longer actively hosts it) | ☑ pass | took three fix rounds to clear, each one step further down the pipeline: MM-301 → MM-302 → MM-304 (see bugs list). Curl outputs in session transcript + MM-241 comment |
| (c) hop staging → production | 2026-07-12 19:45 | mal | wallet (same TestFlight build as leg (b), on device; both ends v0.4.5-train) | ✅ newest op `createdAt` 2026-07-12T19:45:56.147Z, not nullified; **self-signed**; `rotationKeys[0]` = `WALLET_KEY` (third PLC op it survives), [1] = production's recommended key `did:key:zDnaepBn1v6K4awycKx8J5rnSACoAf6QgsYon6YEFY8jD4p6R`; `atproto_pds` → `https://obsign.org` | ✅ production `getRepoStatus` `active: true` rev `3mqdcm57v4u22`; staging reports `deactivated` at the **same rev** (lossless handoff, no fork) | ☑ pass | zero new walls — first leg needing no code changes. Pre-flight snag (no code fix): source account had no password (MM-306) and a typo'd email (MM-308) — unblocked via `requestPasswordReset` + token from staging Railway logs (log-only email sender); MM-309 filed for operator repair ops. Curl outputs in session transcript + MM-241 comment |
| (d) return production → staging | — | — | wallet (device) | — | — | ☐ pass ☐ fail | — |

DIDs used: `did:plc:u7j7xdhvkwx3xlf6xjkbpdn7` (`malpercio-obsign.bsky.social`, dedicated test account)
Bugs filed — leg (a) attempts: MM-288 (OAuth client_id/redirect reverse-FQDN), MM-289
(identity scope requires full session), MM-290 (error surfacing), MM-291 (empty body on
no-input procedures), MM-293 (claim DID not registered before device-key lookup), MM-294
(PLC verification was P-256-only). Leg (r) attempts: MM-295 (Custos rejected the RFC 9449
DPoP scheme), MM-297 (consent-page checkboxes outside the form — every OAuth grant reduced
to bare `atproto`), MM-298 (preferences routes rejected deactivated accounts), MM-299
(migration-mode createAccount not resumable), MM-300 (post-migration DID-doc cache stored
the W3C doc — "Unknown" custody badge), plus MM-296 (repo-write DPoP binding gap, adjacent
finding). All fixed and merged before each leg's passing run (server fixes shipped as
v0.4.4; MM-300 is wallet-side, in the next build). Leg (r) also left one stranded
deactivated throwaway on production (`did:plc:qguepidxfcb6tw52czs6tdkf`, pre-MM-299) —
harmless junk.
Legs (b)/(c) attempts: MM-301 (claim flow cached a doc with empty `rotationKeys` — migrate
entry hidden; fix added the canonical `/{did}/data` fetch + home-screen cache self-heal),
MM-302 (outbound source login must be a full password session — bsky refuses
`getServiceAuth(lxm=createAccount)` below the privileged tier; OAuth `transition:generic`
is app-password tier), MM-304 (Custos `verify_service_auth_jwt` was ES256/P-256-only —
bsky signs service-auth JWTs with the account's secp256k1 key, ES256K). All fixed and
merged before leg (b)'s passing run. Follow-on tickets from legs (b)/(c) and the leg (d)
pre-flight: MM-305 (wallet change-handle flow), MM-306 (sovereign passwordless login —
migrated accounts land with no password by design), MM-307 (Custos updateHandle doesn't
push the alsoKnownAs PLC op), MM-308 (email normalization), MM-309 (operator
account-repair ops), MM-310 (DID-doc cache never refreshes; `refreshIdentity` is a no-op —
**the leg (d) blocker**).
Findings / deviations: **Leg (a) as executed was claim-only.** The shipped "Bring an
identity" flow implements the phased custody-first design (wallet key inserted as
`rotationKeys[0]` via bsky.social's email-tokened `signPlcOperation`): it did **not**
create a staging account, repoint `atproto_pds`, or deactivate on bsky.social as the
original runbook's leg (a) described — the account remained fully hosted on bsky.social
with unchanged services. The leg's stated purpose (PDS-signed insertion of the wallet
device key as `rotationKeys[0]`) was proven. This runbook's legs (b)–(d) were rewritten
2026-07-11 accordingly: the remaining hops are wallet-driven and self-signed by the
Secure-Enclave key, replacing the original interop-CLI legs (kept as fallback above).

**bsky.social inbound-migration posture (extra-curricular probe, 2026-07-12).** Not a
runbook leg, but probed after leg (c) while assessing a hypothetical return-to-bsky:
their entryway auth-gates `reserveSigningKey` (public on the reference PDS), applies the
phone-verification gate in front of `createAccount` (`inviteCodeRequired: false`,
`phoneVerificationRequired: true`), and rejected a **provably valid** production-minted
ES256 service-auth token with `InvalidToken: Token could not be verified` — the same token
passes full verification (alg/curve/signature/iss/aud/lxm/exp) against a local Custos
impersonating `did:web:bsky.social`, whose verifier resolves the DID's current `#atproto`
key fresh from plc.directory. Consistent with a stale DID cache on their side (the DID had
two PLC ops that day) and/or an unsupported-inbound-migration policy. Recorded here as the
asymmetry this product exists to break: leaving bsky.social is possible (leg (b)),
returning is not currently accepted. Investigating whether Custos shares the failure mode
found MM-310. Also observed: production's `getServiceAuth` mints 60-second-TTL tokens when
`lxm` is set — fine for the wallet's mint→use gap, tight for manual testing.
