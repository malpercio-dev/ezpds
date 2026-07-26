# Obsign Without Custos — First-Class Any-PDS Wallet Support

**Status: design accepted — issues filed (epic [MM-452](https://linear.app/malpercio/issue/MM-452),
Wave 9: Obsign Anywhere).** Captures the 2026-07-24 strategy session: a survey of
how much of Obsign already functions for identities hosted on a non-Custos PDS, an
ecosystem survey of how other PDS implementations self-identify, and the phased
plan for making the any-PDS tier a deliberate product rather than an accident of
good architecture.

## Summary

Obsign's differentiating features split cleanly along an architectural seam that
already exists in the wallet: `PdsClient` speaks standard ATProto lexicons to
arbitrary hosts and plc.directory, while `CustosClient` speaks the custom `/v1/*`
surface to Custos. Everything riding on the first client — the claim ceremony,
PLC monitoring, the 72-hour recovery override, user-held repo/media backup,
endpoint repair, sovereign share recovery, and (almost) sovereign disaster
recovery — works against any spec-compliant PDS today. Everything on the second
is the natural Custos value tier.

The strategy: **broaden the market by making the free/any-PDS tier explicit and
complete, and let Custos win on its capabilities rather than on lock-in.** A user
on bsky.social or a reference PDS claims their identity, gains a Secure-Enclave
root key plus monitoring plus full data custody, and converts to Custos at the
moments Custos is genuinely better — escrow-assisted recovery, passwordless
sessions, agents, wallet-confirmed consent — never because a flow left them no
other button. In particular, rescue (disaster recovery) must work to any
destination: recovering an account is the worst possible moment to present a
hosting decision with only one viable answer.

## The functional matrix (verified 2026-07-24, v0.8.1 / a21aad8)

For an identity **imported via the claim flow** (device key installed at
`rotationKeys[0]`; see [identity-and-key-custody.md](../architecture/identity-and-key-custody.md)),
hosted on any spec-compliant PDS:

| Works today with zero Custos involvement | Mechanism |
| --- | --- |
| Claim/import (Secure-Enclave key → `rotationKeys[0]`) | Standard lexicons (`createSession`, `requestPlcOperationSignature`, `signPlcOperation`) + plc.directory; validated live against bsky.social (MM-241) |
| 24/7 PLC monitoring + alerts | `plc_monitor.rs`, plc.directory only |
| 72-hour recovery override | `recovery.rs`, device-key-signed counter-op to plc.directory |
| Repo backup (full CAR → iCloud) | `repo_backup.rs`, public unauthenticated `com.atproto.sync.getRepo`, client-side CAR validation (MM-447) |
| Media backup (CID-verified mirror → iCloud) | `blob_backup.rs`, public `listBlobs`/`getBlob` (MM-434) |
| Endpoint repair (`atproto_pds` repoint) | `endpoint_repair.rs`, plc.directory + new-host probe only |
| Sovereign share recovery (two self-held shares) | `share_recovery.rs`, plc.directory only until re-escrow |
| Disaster recovery **into a Custos destination** | `disaster_recovery.rs`: offline service-auth JWT verified via plc.directory, standard transfer legs, iCloud mirrors (MM-451) |

| Custos-locked today | Lock type |
| --- | --- |
| Create-new-identity ceremony (`/v1/accounts/mobile`, `/v1/dids`) | Structural — standard `createAccount` never lets the client author genesis rotation keys |
| Shamir generation / re-key (fused to `/v1/dids` + `PUT /v1/recovery/escrow-share`) | Incidental — separable (Phase 1) |
| Escrow-assisted recovery (`/v1/recovery/*`) | Inherent — escrow *is* the Custos service |
| Sovereign sessions (`/v1/sessions/sovereign`) and everything downstream: app passwords, change handle, removal, **blob restore** | Incidental — the features are standard lexicons; only the unlock path is Custos (Phase 2) |
| Rescue/migration **destination** (finalize unconditionally mints the sovereign session) | Incidental — one branch (Phase 3) |
| Agents (auth.md), wallet-confirmed OAuth consent, repo-key rotation, did:web hosting | Inherent — Custos server capabilities |

What changed since the previous look (v0.7.x): the user-held backup wave
(MM-434/444/445/447), the migration mirror fallbacks (MM-433/446/448), sovereign
disaster recovery (MM-451), and endpoint repair — together these shipped most of
the free tier and the strongest conversion mechanic (dead-PDS rescue) without
"any-PDS support" ever being the stated goal.

## Ecosystem survey: how do PDS implementations identify themselves?

Surveyed 2026-07-24 to decide whether to invent a detection mechanism or adopt
an existing one. Conclusion: there is nothing to adopt; there is a precedent to
follow.

- **Reference TypeScript PDS** (bsky.social, probed live; and the self-host
  distribution): `describeServer` returns strictly the lexicon fields. The only
  software signal anywhere is `GET /xrpc/_health` → `{"version": …}` — on
  bsky.social a bare git commit hash, no software name.
- **millipds** (Python): the direct precedent. Its `describeServer` adds an extra
  field the source comments `# off-spec`: `"version": "millipds v0.x"`. The same
  identifying string appears in `_health` and its outgoing `User-Agent`.
- **rsky-pds** (Blacksky, Rust): strictly spec-conformant `describeServer`,
  field-for-field with the reference; no identification of any kind.
- **Spec position** ([Lexicon spec](https://atproto.com/specs/lexicon)):
  "Unexpected fields in data which otherwise conforms to the Lexicon should be
  ignored. When doing schema validation, they should be treated at worst as
  warnings." The stated caveat: a third-party field name can collide if the
  lexicon authority later claims the same name with different semantics.
- No nodeinfo-style convention exists in atproto; diagnostic tooling
  fingerprints by probing endpoints and reading `_health`.

Design consequences: extending `describeServer` is safe and precedented; the
extension should live under a single distinctively-named key (`custos`) rather
than generic top-level names (`capabilities`, `software`, `version` — millipds
has already claimed `version` with its own semantics, demonstrating the
collision hazard); and `_health` should carry a `custos vX.Y.Z`-style string,
matching the one quasi-convention that exists.

## Design

### Capability detection ([MM-454](https://linear.app/malpercio/issue/MM-454))

Custos's `describeServer` output gains a namespaced extension object:

```json
{
  "did": "…",
  "availableUserDomains": ["…"],
  "custos": {
    "version": "0.8.1",
    "capabilities": [
      "createCeremony", "escrow", "sovereignSessions",
      "agents", "walletConsent", "didWebHosting"
    ]
  }
}
```

Named capabilities, not an `isCustos` boolean: a self-hosted Custos may run with
escrow disabled; a future implementation could adopt a single capability; and
every wallet gate reads as "does this host advertise X?" rather than "is this
ours?". The wallet's `DescribeServerResponse` gains the optional field, cached
per host; an absent field means no capabilities — standard-lexicon behavior —
which cleanly covers every implementation surveyed above. `_health` becomes
self-identifying (`custos v0.8.1`).

**Shipped.** The server-side source of truth is `crates/pds/src/capabilities.rs`:
a `CAPABILITIES` table whose entries carry the wire name, the config that gates
the capability, a one-line summary, and the predicate that reads the live
`Config` — the same condition the routes themselves enforce, so advertisement
cannot promise what a caller would be refused. Today `createCeremony` and
`escrow` require a configured master key (both store material under the master
KEK), `agents` requires at least one `[agent_auth]` registration flow to be
enabled (all off by default), and `sovereignSessions` / `walletConsent` /
`didWebHosting` are inherent to running Custos. That table also feeds the
generated operator reference page and a CI gate (`just capability-docs-check`)
that fails if a capability is added, renamed, or re-gated without the
hand-written operator capabilities page moving in the same change. On the wallet
side, `pds_capabilities.rs` holds the per-host cache, warmed by *every*
`describe_server` call rather than a dedicated probe, and surfaced to the
frontend as `getPdsCapabilities()`; a failed probe reports no capabilities and is
deliberately **not** cached, so a transient outage never freezes into a permanent
verdict.

### Phase 0a — mode-select honesty ([MM-453](https://linear.app/malpercio/issue/MM-453))

`ModeSelectScreen` renames "Add an identity" → **"Create an identity"**, and
"Move an identity to another PDS" → **"Import an identity"** — the second is not
a rewording but a correction: that button launches the claim flow, which takes
sovereign custody of an identity that stays on its current PDS. The current
label describes a different feature and hides the front door for non-Custos
users. Additionally, when the configured PDS lacks the `createCeremony`
capability, the create entry explains honestly that creation needs a Custos
server and steers to import — up front, not as a late `/v1/accounts/mobile`
error.

### Phase 0c — positioning + validation ([MM-455](https://linear.app/malpercio/issue/MM-455))

Validation before marketing: run the full arc — claim from a reference PDS →
enable backups → source PDS dies → disaster-recovery rebuild — as one journey
(it is composed of individually-tested parts but has never been executed as
*the* journey), write the validation doc, then land the "Obsign for any PDS"
story on the marketing and docs sites with the import flow as the documented
entry point.

### Phase 1 — self-held Shamir kit ([MM-456](https://linear.app/malpercio/issue/MM-456))

An escrow-less re-key variant for foreign-hosted root-key identities:
client-side seed + 2-of-3 split (reusing `share_ceremony.rs`, whose generation
is already pre-network), derived recovery key inserted after the device key via
a device-key-signed plc.directory op, Share 1 to the iCloud Keychain per-DID
slot, Shares 2 and 3 to the user. A new strict guard is required —
`guard_rekey_op` assumes the exact pre-inversion `[device, PDS]` layout and the
flow hard-requires the escrow deposit, while a claimed identity has arbitrary
existing rotation keys. The existing sovereign recovery ceremony then works
unchanged (its epilogue skips re-escrow on hosts without the `escrow`
capability). The upsell seam is a single post-completion prompt, not pressure.

**Shipped.** `apps/identity-wallet/src-tauri/src/self_held_kit.rs`, with
`guard_self_held_kit_op` as the seventh strict allowlist. The one design decision
the plan left open was resolved by *gating* rather than layering: the flow refuses
with `HOST_OFFERS_ESCROW` on a host advertising `escrow`, so the two ceremonies
are disjoint by capability and `rekey.rs` is untouched. A host that could not be
*asked* is deliberately not refused — `probe` does not cache an unreachable
verdict, and treating an outage as "escrow exists" would strand a user behind a
network blink on the one flow that needs no server. The same asymmetry now governs
the recovery epilogue's re-escrow leg (`share_recovery::host_offers_escrow`):
answered-and-no-escrow skips as a fact about the server, unreachable still
attempts, because silently dropping the leg would downgrade a Custos account's
posture. Shares 2 and 3 both reach the user through the create ceremony's
`ShamirBackupScreen`, which gained an optional `share2` prop — passing it is what
turns "save one share" into "save two" and replaces the escrow line. The upsell
seam is the durable `{did}:self-held-kit` marker plus
`self_held_kit_escrow_offer_cmd`, true only once the identity's *current* host
advertises `escrow`; by construction it is never true right after a kit completes.
Harness scenarios: `self-held-kit`, `self-held-kit-escrow-host`.

### Phase 2 — foreign-PDS sessions ([MM-457](https://linear.app/malpercio/issue/MM-457))

`SessionProvider`'s `NeedsUnlock` gains a second resolution: on hosts without
`sovereignSessions`, a password `createSession` prompt (the transient machinery
`source_login.rs` already uses), persisting the Bearer pair in the same
versioned `{did}:oauth-tokens` record so the provider's refresh ladder is
unchanged. This lights up app passwords, change handle, identity removal, and
blob restore for foreign identities — all already standard-lexicon features that
are dark only for want of a session. ADR-0021's full-session requirement and the
use-once-never-store password posture both hold.

### Phase 3 — any-PDS rescue destination ([MM-458](https://linear.app/malpercio/issue/MM-458))

`finalize_migration_core`'s injected `ensure_session` step branches on the
destination's `sovereignSessions` capability: present → today's sovereign-session
mint; absent → durably persist the Bearer session already held from the
migration `createAccount`, preserving the strict
activate → durable-credential → deactivate ordering. One branch serves both
sovereign disaster recovery to a non-Custos destination and outbound migration
between arbitrary hosts. This is a deliberate strategic choice: the rescue path
must not be a lock-in funnel, which paradoxically strengthens the Custos pitch —
conversion happens because escrow/agents/consent are worth it, with trust intact.

## Sequencing and rationale

0a/0b/0c are cheap and independent (0a's gate consumes 0b's probe but has a
degraded interim form). Phase 1 completes the "benefits without Custos" story —
the one genuinely missing free-tier piece. Phase 2 removes the daily-driver
friction that would otherwise make the free tier feel broken the first time a
user taps App Passwords. Phase 3 is smallest in code and largest in positioning.

## Parked (explicitly out of scope, needs its own design pass)

**Create-then-sovereignize:** "Create an identity" on a *reference* PDS could
mean standard `createAccount` followed immediately by the claim ceremony to
install the device key. It would make creation PDS-agnostic, but the resulting
identity starts without the recovery slot and with the old PDS's key layout, so
its guard/ceremony interactions (and the honest framing of what it does and
doesn't guarantee) deserve a dedicated plan.

## Traceability

Epic [MM-452](https://linear.app/malpercio/issue/MM-452) (label
`Wave 9: Obsign Anywhere`), children
[MM-453](https://linear.app/malpercio/issue/MM-453) (0a),
[MM-454](https://linear.app/malpercio/issue/MM-454) (0b),
[MM-455](https://linear.app/malpercio/issue/MM-455) (0c),
[MM-456](https://linear.app/malpercio/issue/MM-456) (1),
[MM-457](https://linear.app/malpercio/issue/MM-457) (2),
[MM-458](https://linear.app/malpercio/issue/MM-458) (3).

Related: [ADR-0001](../architecture/decisions/0001-client-held-rotation-key-custody.md)
(custody model), [ADR-0002](../architecture/decisions/0002-wallet-authorized-account-migration.md)
(wallet-authorized migration), [ADR-0021](../architecture/decisions/0021-identity-ops-require-full-session.md)
(full-session requirement), the key-recovery design
([2026-07-17-key-recovery-from-shares.md](../archive/design-plans/2026-07-17-key-recovery-from-shares.md)),
the repo-backup design
([2026-07-22-wallet-repo-icloud-backup.md](2026-07-22-wallet-repo-icloud-backup.md)),
and the passwordless exploration
([2026-07-12-passwordless-auth.md](2026-07-12-passwordless-auth.md), MM-312 —
orthogonal, Custos-side).
