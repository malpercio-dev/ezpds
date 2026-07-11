# MM-241 live migration round trip — runbook + record

**Status: PREPARED — not yet executed.** This document is both the checklist for the live
bsky.social migration round trip and, after execution, the permanent record of the run.
A human operator executes or supervises every leg: the run touches the real plc.directory,
the real bsky.social, and permanent `did:plc` state.

- Ticket: [MM-241](https://linear.app/malpercio/issue/MM-241) (the canonical MM-207 e2e; the
  one unvalidated leg of the migration epic)
- Design: [ADR-0002](../architecture/decisions/0002-wallet-authorized-account-migration.md),
  design plan [v0.1 operational proof](../archive/design-plans/2026-07-07-v01-operational-proof.md)
  (op-proof.AC4)
- Tooling: [`tools/interop`](../../tools/interop/README.md) (`migrate perform` / `migrate
  verify`), the Obsign wallet (inbound leg), `curl` + `jq` for the plc.directory audit checks

## The round trip

| Leg | From → To | Driver | What it proves |
|---|---|---|---|
| (a) Inbound | bsky.social → ezpds staging | Obsign wallet UI (or goat as fallback) | PDS-signed insertion path: bsky.social's email-tokened `signPlcOperation` inserts the wallet's device key as `rotationKeys[0]` |
| (b) Outbound, self-signed | ezpds staging → ezpds production | `just interop migrate perform` | **The differentiator**: the wallet-held rotation key self-signs the PLC op; no PDS custody of the identity |
| (c) Return | ezpds production → ezpds staging | `just interop migrate perform` | Round-trip closure; nothing about the identity degraded |

Deployments: staging `https://ezpds-staging.up.railway.app`, production
`https://obsign.org`.

## Required pass conditions — checked after EVERY leg

A leg is **not passed** because "the commands ran". Both checks below must be recorded per
leg (these are MM-241's acceptance criteria):

**1. plc.directory audit log shows the correct new entry for the hop.**

```sh
DID="did:plc:..."   # the migrating identity
curl -s "https://plc.directory/$DID/log/audit" | jq '.[-1] | {createdAt, nullified, operation: {rotationKeys: .operation.rotationKeys, pds: .operation.services.atproto_pds.endpoint}}'
```

Expected per leg:
- after (a): `rotationKeys[0]` is the **wallet device key** (`did:key:zDn...` held by Obsign);
  `atproto_pds.endpoint` = staging URL; entry not nullified.
- after (b): `atproto_pds.endpoint` = production URL; the op was **signed by the wallet key**
  (it must still be present in `rotationKeys`; custody unchanged).
- after (c): `atproto_pds.endpoint` = staging URL; wallet key custody still unchanged.

**2. Handle, DID document, and repo all resolve correctly against the new host.**

```sh
HANDLE="<the account handle>"
NEW_PDS="https://obsign.org"   # the leg's destination

# Handle → DID (on the new host)
curl -s "$NEW_PDS/xrpc/com.atproto.identity.resolveHandle?handle=$HANDLE" | jq .

# DID document points at the new host
curl -s "https://plc.directory/$DID" | jq '.service[] | select(.id=="#atproto_pds").serviceEndpoint'

# Repo serveable from the new host
curl -s "$NEW_PDS/xrpc/com.atproto.sync.getLatestCommit?did=$DID" | jq .
```

For legs (b) and (c), `migrate verify` performs equivalent checks — run it *and* record the
audit-log check:

```sh
just interop migrate verify --name primary --target-pds "$NEW_PDS"
```

**If a leg fails:** record the failure below, file a bug (its own Linear issue, linked to
MM-241), and **stop the run**. Do not paper over a failed check to reach the next leg.

## Preconditions

- [ ] Both ezpds deployments healthy:
      `curl -s https://ezpds-staging.up.railway.app/xrpc/_health` and the production
      equivalent return 200. Staging sleeps when idle — hit it once and wait for wake.
- [ ] Interop CLI installed: `just interop-setup` (Node ≥ 22.12 via the devenv shell).
- [ ] `EZPDS_ADMIN_TOKEN` for **both** deployments at hand (account creation on the
      destination mints claim codes; see per-leg notes).
- [ ] A dedicated **bsky.social test account** for the run (never the operator's real
      account), with an email inbox you control (leg (a) requires bsky.social's email token).
- [ ] Obsign wallet build on a device/simulator, signed in, holding its device key
      (leg (a)'s driver; also the custodian of the rotation key for legs (b)/(c)).
- [ ] `tools/interop/.state/state.json` backed up **before starting** (it will hold the
      did:plc rotation private key — the actual root of control; treat like a key file).
- [ ] Time budgeted: plc.directory writes are permanent; there is no dry-run mode.

## Rollback notes for the live account

There is no "undo" for a PLC op — rollback means **executing the reverse migration**, which
is exactly leg (c). If the run aborts between legs:

- After (a) only: the identity lives on staging with wallet-key custody. Acceptable
  steady-state for a test identity; optionally migrate back to bsky.social with the wallet.
- Mid-(b) failure (account created on target but DID not repointed): the source account is
  still authoritative. Deactivate the half-created destination account
  (`deactivateAccount` on the target) and retry after the bug is fixed; `migrate perform`
  is resumable in that its early steps are idempotent (reserved key, created-but-inactive
  account), but always re-run `migrate verify` against the *source* first to confirm the
  DID never moved.
- The bsky.social account: leg (a) deactivates it on bsky.social but its data remains
  exportable for 30+ days per Bluesky policy; nothing here deletes it.
- Worst case (wallet/device key lost mid-run): `state.json` (backed up above) holds the
  interop-managed rotation key for the `primary` interop identity; the migrating test
  identity's recovery follows the wallet's recovery-share flow.

## Leg (a) — inbound: bsky.social → ezpds staging

Driver: the Obsign wallet's inbound-migration flow (MM-232). There is deliberately no
interop-CLI driver for this leg. Fallback if the wallet flow is blocked: `goat account
migrate` (standard tooling) against ezpds as destination — record which driver was used.

1. In the wallet: start "Bring an identity" (inbound migration) targeting the bsky.social
   test account; destination = staging.
2. The flow will: create the deactivated destination account on staging (service-auth),
   `importRepo` + drain blobs + preferences, then request the **PDS-signed** PLC op from
   bsky.social — `requestPlcOperationSignature` emails a token to the account inbox; enter
   it in the wallet. The signed op must insert the wallet device key as `rotationKeys[0]`
   (ahead of bsky.social's recommended keys) and repoint `atproto_pds` to staging.
3. Submit; activate on staging; deactivate on bsky.social.
4. **Record both pass conditions above.** Specifically confirm `rotationKeys[0]` is the
   wallet key — this custody handoff is the entire point of the leg.

## Leg (b) — outbound self-signed: staging → production

```sh
export EZPDS_BASE_URL="https://ezpds-staging.up.railway.app"   # source
export EZPDS_ADMIN_TOKEN="<staging admin token>"               # only if the account below is being created fresh

# One-time, if the migrating identity is not yet an interop-managed account on staging —
# for the MM-241 run the identity from leg (a) is adopted per the wallet flow; otherwise:
just interop create-account --name primary

just interop migrate perform --name primary --target-pds https://obsign.org
just interop migrate verify  --name primary --target-pds https://obsign.org
```

Notes:
- `migrate perform` runs the 12-step flow (reserve key on target → service-auth create →
  importRepo → blob drain → preferences → **self-signed** PLC op → submit → activate/
  deactivate). The PLC op is signed with the **locally held** rotation key — the source PDS
  never signs. That's the differentiator being proven.
- The destination (production) enforces invite codes: have the production
  `EZPDS_ADMIN_TOKEN` ready if the flow asks for a claim code.
- `migrate perform` writes a JSON report under `tools/interop/.state/reports/` — link it in
  the record below.
- **Record both pass conditions above** (audit log + resolution against production).

## Leg (c) — return: production → staging

```sh
export EZPDS_BASE_URL="https://obsign.org"   # source is now production
just interop migrate perform --name primary --target-pds https://ezpds-staging.up.railway.app
just interop migrate verify  --name primary --target-pds https://ezpds-staging.up.railway.app
```

Note: the interop CLI's other commands keep targeting `EZPDS_BASE_URL`, not the per-account
`pds` recorded in state — set the env var per leg as shown (see the interop README's
migration note).

**Record both pass conditions above** (audit log + resolution against staging).

## Post-run

- [ ] `just interop suite --no-interact` against staging passes with the migrated-back
      account (steady-state sanity).
- [ ] Reports linked below; `state.json` backup rotated.
- [ ] MM-241: closed with a link to this document, **or** a blocking bug filed and linked.

## Execution record

> Fill in during the run. A leg without both recorded checks is not passed.

| Leg | Date (UTC) | Operator | Driver | Audit-log check | Resolution check | Result | Artifacts |
|---|---|---|---|---|---|---|---|
| (a) inbound | — | — | wallet / goat | — | — | ☐ pass ☐ fail | — |
| (b) outbound self-signed | — | — | interop CLI | — | — | ☐ pass ☐ fail | report: — |
| (c) return | — | — | interop CLI | — | — | ☐ pass ☐ fail | report: — |

DIDs used: —
Bugs filed: —
Findings / deviations: —
