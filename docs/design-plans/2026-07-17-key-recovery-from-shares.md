# Key Recovery from Shamir Shares — With and Without Escrow Assistance

Status: **accepted for implementation** — tracked in Linear as
[MM-405](https://linear.app/malpercio/issue/MM-405) (epic), with children
[MM-406](https://linear.app/malpercio/issue/MM-406) (crypto primitives),
[MM-407](https://linear.app/malpercio/issue/MM-407) (ceremony inversion + ordering ADR),
[MM-408](https://linear.app/malpercio/issue/MM-408) (escrow storage; absorbs MM-378),
[MM-409](https://linear.app/malpercio/issue/MM-409) (escrow release flow),
[MM-410](https://linear.app/malpercio/issue/MM-410) (wallet recovery ceremony),
[MM-411](https://linear.app/malpercio/issue/MM-411) (existing-account re-key), and
[MM-412](https://linear.app/malpercio/issue/MM-412) (docs truth-up, immediately
actionable). MM-405 blocks MM-312 (passwordless). Captures the
recovery-ceremony discussion of 2026-07-17 (capture-before-close). Builds on
[ADR-0001](../architecture/decisions/0001-client-held-rotation-key-custody.md),
[ADR-0002](../architecture/decisions/0002-wallet-authorized-account-migration.md), and the
[passwordless-auth exploration](2026-07-12-passwordless-auth.md), which flagged the Shamir
reconstruction ceremony as a **hard prerequisite** for removing the password.

## Problem

Every layer of the stack promises share-based recovery, and none of it can currently
recover anything:

- ADR-0001 names the mitigation for its "user key loss" failure mode: "2-of-3 Shamir
  splitting of the device key at onboarding … Full 2-of-3 recovery ceremony is future
  work."
- The docs site tells users "Obsign brings any two shares back together and reconstructs
  the recovery key on your device" ([user/backup.md](../../sites/docs/src/content/docs/user/backup.md)) —
  a flow that does not exist.
- The V046 admin-repair doctrine refuses password-reset tokens for passwordless accounts
  because "a key-sovereign account is recovered through its escrowed key share."

This document audits what actually ships today, names the gaps, and designs the two
recovery paths the split was always meant to enable:

- **With escrow assistance** — lost phone, iCloud intact: Share 1 (iCloud) + Share 2
  (Custos escrow) recover on a new device, with the server as a *release gate*.
- **Without escrow assistance** — Custos dead, hostile, or simply not trusted: Share 1 +
  Share 3 (user's copy) recover with **zero** server involvement, composing with
  ADR-0002's wallet-authorized migration for full credible exit.

## Current state (as-built audit)

**The crypto layer is solid.** `crates/crypto/src/shamir.rs` implements a hardened 2-of-3
split of a 32-byte secret over GF(2^8) (branchless reduction on secret bytes, zeroized
share material, information-theoretic single-share security). `split_secret` /
`combine_shares` are tested and ready.

**The distribution plumbing works as designed.** The `/v1/dids` ceremony
(`crates/pds/src/routes/create_did.rs`) generates shares, returns Shares 1 and 3 to the
wallet, and commits Share 2 to `accounts.recovery_share` (V010) atomically with
promotion. Retries are idempotent via `pending_accounts.pending_share_{1,2,3}` (V011).
The wallet stores Share 1 in the iCloud-synced Keychain (`recovery-share-1`) and walks
the user through saving Share 3 (`ShamirBackupScreen`, confirm-before-continue).

**But the model has five gaps, in severity order:**

1. **The secret is bound to nothing.** `generate_recovery_shares()` splits a *fresh
   random 32 bytes*. That secret is not a rotation key, does not appear in the DID's
   `rotationKeys`, and encrypts nothing. Reconstructing it recovers a random number.
   The device key it was nominally protecting lives in the Secure Enclave and is
   non-extractable — it never could have been the split's input on real hardware.

2. **The escrow agent generated the secret.** The split runs *server-side*: the PDS saw
   the secret and all three shares at ceremony time, and `pending_accounts` holds all
   three in plaintext until promotion — which means Litestream backups and WAL history
   retain complete reconstruction material for every account that ran the ceremony.
   Today's impact is nil only because of gap 1: the moment the secret is bound to real
   authority, server-side generation breaks the sovereignty claim ("the PDS holds at
   most one share" — [data-migration-spec](../data-migration-spec.md)) for every
   existing account, retroactively and unfixably for anyone holding old backups.

3. **The specs describe an impossible reconstruction.** The
   [mobile spec §7](../mobile-architecture-spec.md) says recovery "reconstruct[s the]
   root key in new Secure Enclave" — SE keys cannot be imported. And
   [identity-and-key-custody.md](../architecture/identity-and-key-custody.md) says "the
   crypto crate splits the device key 2-of-3" — wrong on both counts (not the device
   key; not split client-side). The correct model (below): the reconstructed seed
   derives a *separate software rotation key*; the new device's SE key is fresh and gets
   *installed* by a PLC op that the recovery key signs.

4. **Bare share format.** Shares are 52 base32 chars of raw payload: no version, no
   share-set id, no index, no checksum. The index isn't even encoded — holders must
   remember which share they are by storage location. Two shares from different
   generations (e.g. after a future rotation) would combine into silent garbage.

5. **Escrow storage is outside the KEK envelope.** `accounts.recovery_share` is
   plaintext TEXT — not in `db/kek.rs`'s `SecretFamily::ALL`, so master-key rotation
   doesn't cover it. A lone share is information-theoretically useless, so this is
   defense-in-depth rather than a break, but it's an inconsistency with every other
   secret column.

## Design

### 1. Bind the seed to real authority: a derived recovery rotation key

The 32-byte secret becomes a **recovery seed**. From it, derive a P-256 keypair
(HKDF-SHA256 with a fixed domain-separation info string → scalar, rejection-sampled into
the curve order), and place its `did:key` in the DID's `rotationKeys`:

```
rotationKeys: [ device key (SE),  recovery key (derived),  PDS key ]
                    [0]                  [1]                 [2]
```

Now reconstruction ⇒ a private key that plc.directory already recognizes as an identity
controller. Two properties fall out for free:

- **Verifiable reconstruction.** Derive the public key from the combined seed and compare
  against the DID's authoritative `rotationKeys` — the wallet can tell the user "these
  two shares are correct" (or not) using only public information, before signing anything.
- **Passwordless session bootstrap.** `POST /v1/sessions/sovereign` accepts a proof
  signed by *any* current PLC rotation key. A recovered wallet can authenticate to
  Custos with the recovery key immediately after reconstruction — before the
  key-replacement PLC op even lands. The recovery ceremony and the passwordless design
  compose instead of colliding.

**Why recovery sits below the device key.** Priority only matters inside plc.directory's
72-hour override contest. Ordering `[device, recovery, PDS]` means: a *lost* device is
recoverable (no contest — the recovery key can freely sign the op replacing it); a
*compromised share pair* (iCloud + escrow, i.e. a malicious operator colluding with an
Apple-account compromise) can still be overridden by the genuine device within 72 hours
— the Secure Enclave stays supreme, which is the ADR-0001 posture. The alternative
(`[recovery, device, PDS]`) would protect against a stolen-and-unlocked device at the
cost of letting a share-collecting operator outrank the user's enclave; that inverts the
project's core custody claim. (An attacker who can sign with the SE key already owns the
unlocked device + biometrics — a stronger position than any share pair, and one no
ordering fixes.) Held as an open question below, but the recommendation is firm.

### 2. Move generation client-side

The wallet's Rust core already links `crates/crypto`. The ceremony changes:

- The **wallet** generates the seed, derives the recovery key, splits the seed 2-of-3,
  and includes the recovery `did:key` in the genesis op's `rotationKeys` (it already
  builds and signs the genesis op via `build_did_plc_genesis_op_with_external_signer`).
- `/v1/dids` **stops generating and returning shares** (`shamir_share_1/3` leave the
  response; `pending_share_{1,2,3}` and the server-side `generate_recovery_shares` are
  retired). The server receives exactly one share — Share 2 — in the ceremony request
  (or an immediately-following authenticated `PUT`), and never sees the seed or the
  other shares.
- Retry-resilience moves where the material now lives: the wallet persists the seed +
  shares (Keychain, non-synced slot) until the ceremony is confirmed complete, then
  zeroizes the seed and Share 2's local copy.

This closes gap 2 structurally: reconstruction material never exists server-side, so no
DB snapshot, backup, or hostile operator can ever hold two shares.

### 3. Versioned share envelope

Replace bare base32 with a self-describing envelope (still base32/QR-friendly):

```
version(1B) || set_id(4B) || index(1B) || payload(32B) || checksum(4B, SHA-256 prefix over the preceding bytes)
```

- `set_id`: random per split-generation; `combine` refuses shares from different sets
  loudly instead of reconstructing garbage (fixes gap 4, prerequisite for rotation).
- `index`: carried in-band; holders no longer identify shares by storage location.
- Share 3 additionally gets a **BIP-39-style word rendering** for the human-custody copy
  (the mobile spec always envisioned this); Shares 1/2 stay machine-format.
- `crates/crypto` gains `encode_share`/`decode_share` plus the HKDF
  `derive_recovery_keypair(seed)`; the GF(2^8) core is unchanged.

### 4. Recovery ceremony A — with escrow assistance

The common case: lost/dead phone, iCloud intact, Custos alive and honest.

1. **New device, fresh install** → "Recover existing identity." Share 1 appears
   automatically via iCloud Keychain sync.
2. **Escrow release request.** `POST /v1/recovery/initiate` with handle/DID → server
   emails an OTP to the account address (always-200, no enumeration — the
   `requestPasswordReset` pattern; real delivery exists since MM-211).
   `POST /v1/recovery/release` with the OTP → returns Share 2. Every step: tight
   per-IP rate limits, audit events, and a notification to the account email.
3. **Release delay (default on, operator- and user-configurable).** The release sits
   `pending` for a window (e.g. 24h) during which any authenticated session/device can
   cancel — a push through the [notification relay](2026-07-10-notification-relay.md)
   when that lands, email links meanwhile. Rationale: escrow release converts
   "iCloud + mailbox compromise" into identity compromise; the delay plus the device
   key's 72-hour override supremacy (ordering above) are the two backstops. A requester
   who can't wait can skip the delay by proving possession of Share 3 — at which point
   they hold two shares and never needed escrow.
4. **Reconstruct + verify.** Combine Shares 1+2 → seed → derive keypair → compare the
   public key against plc.directory's current `rotationKeys`. Mismatch = wrong/stale
   shares, fail loudly before any signature.
5. **Re-anchor the identity.** The new device generates a fresh SE device key; the
   recovery key signs a PLC rotation op replacing the old device key at
   `rotationKeys[0]` with the new one. Sovereign session via the recovery key
   bootstraps Custos auth for the new device's session/device registration.
6. **Rotate the shares.** Mandatory ceremony epilogue: new seed, new split, new
   recovery key replacing the old at `rotationKeys[1]` (same or follow-up op, signed by
   the new device key), new Share 2 re-escrowed over the authenticated session, Share 1
   rewritten to Keychain, user walked through saving the new Share 3. The lost device's
   world — old Share 1 copy, old escrow, old Share 3 — is fully void.

### 5. Recovery ceremony B — without escrow assistance

The credible-exit case: Custos is down, hostile, or the user simply doesn't want to ask.

1. Share 1 (iCloud Keychain) + Share 3 (manual entry / QR / word-phrase) combine
   **entirely on-device**. No Custos endpoint is touched.
2. Verify against plc.directory as above (the only network dependency).
3. The recovery key signs PLC op(s) that: install the new device key, and — when the
   old PDS is gone — repoint `services.atproto_pds` and swap
   `verificationMethods.atproto` to a new host's keys. This is exactly ADR-0002's
   wallet-authorized migration with the recovery key standing in for the lost device
   key. Repo data restoration then follows the standard import path
   (`getRepo` from relay/AppView mirrors, `importRepo` at the new host).
4. Share rotation epilogue as in ceremony A (escrow upload goes to whichever PDS the
   identity now points at).

**What escrow alone can never do — by design.** Custos holds one share and the
lowest-priority rotation key. A pure-escrow "recovery" is impossible (one share reveals
nothing), and the PDS's own `rotationKeys[2]` remains only the interop-grade,
email-tokened `signPlcOperation` lever it is today — overridable by both keys above it.
Both properties should be stated in the docs as guarantees, not caveats.

### 6. Server surface (sketch)

| Endpoint | Auth | Purpose |
|---|---|---|
| `PUT /v1/recovery/escrow-share` | account owner (session / sovereign session) | store or replace Share 2; used at ceremony, rotation, and old-model migration |
| `POST /v1/recovery/initiate` | public, rate-limited | handle/DID → email OTP; always-200 |
| `POST /v1/recovery/release` | OTP | enter `pending` (delayed) or return Share 2; audit + notify |
| `POST /v1/recovery/release/cancel` | any account session/device | kill a pending release |
| `DELETE /v1/recovery/escrow-share` | account owner | opt out of escrow entirely (Shares 1+3 remain the only path) |

Storage moves from the `accounts.recovery_share` column to a `recovery_escrow` table
(share envelope ciphertext, created/rotated timestamps, release state machine) plus an
append-only `recovery_audit_events` (modeled on `agent_audit_events`). The escrowed
share is AES-256-GCM-wrapped under the master KEK and **registered in
`SecretFamily::ALL`** so `rewrap-master-key` covers it (fixes gap 5).
`account_delete::purge_account` deletes both tables' rows.

### 7. Migrating existing accounts

Every pre-existing account has an unbound, server-generated split — worthless as-is and
tainted per gap 2. The wallet detects the old model (no recovery key in `rotationKeys`)
and runs a **re-key**: generate seed client-side, device-key-signed PLC op inserts the
recovery key at `[1]`, `PUT` the new Share 2 (server drops `accounts.recovery_share`),
rewrite Keychain Share 1, walk the user through saving the new Share 3 (reusing
`ShamirBackupScreen`). Until re-key, the account's real safety net is unchanged from
today: the device key itself. Old shares are voided by the re-key, not merely rotated —
which is the honest framing, since they never protected anything.

## Implementation seams (verified 2026-07-17)

A pre-scheduling pass over the actual code confirmed the design lands on friendly seams:

- **The genesis builder is the only hard-coded constraint.**
  `build_did_plc_genesis_op[_with_external_signer]` fixes
  `rotation_keys: vec![rotation_key, signing_key]`; a multi-key variant is needed
  (MM-406). The server's `verify_and_validate_genesis_op` only pins `rotationKeys[0]`
  and non-emptiness — a third key already passes validation unchanged.
- **PLC's cap is 1–5 rotation *keys*** (not rotation operations). The proposed layout
  spends 3 of 5 slots, deliberately leaving headroom for a second device or
  successor-key arrangement; k-of-n growth stays inside the one recovery key.
- **Sovereign session needs zero changes** for the recovery-key bootstrap:
  `/v1/sessions/sovereign` already verifies against the authoritative current PLC
  `rotationKeys`, any key qualifying.
- **Established patterns cover the new server surface:** the OTP reuses the hashed
  single-use 1-hour token envelope (V014/V033/V034/V036); the release pair shares one
  per-endpoint IP limiter instance (the agent claim-pair precedent); the audit trail
  copies `agent_audit_events` (V040, append-only); the escrow ciphertext registers as a
  new `SecretFamily` variant so `rewrap-master-key` covers it (absorbing MM-378).

## Suggested phasing (when scheduled)

1. **Crypto + format** (`crates/crypto`): share envelope v2 (encode/decode, set-id
   check), `derive_recovery_keypair`. Pure, fully testable offline.
2. **Ceremony inversion**: wallet-side generation/split, recovery key in genesis
   `rotationKeys`, `PUT /v1/recovery/escrow-share`, retire server-side generation +
   `pending_share_*`, escrow table + KEK wrapping, re-key flow for existing accounts.
   Spec/docs corrections (identity-and-key-custody.md, mobile spec §7, user backup.md).
3. **Recovery ceremonies**: wallet "Recover existing identity" onboarding branch
   (both A and B paths share reconstruction/verification/re-anchor code), escrow
   release endpoints with OTP + audit + notification, share-rotation epilogue.
4. **Hardening**: release-delay state machine with cancel (push via the notification
   relay once it lands), periodic "verify your Share 3" health-check prompts, docs-site
   recovery runbook.

Phases 1–2 are the passwordless plan's hard prerequisite in buildable form; the
passwordless Phase 1 should not ship before them.

## Open questions

- **Rotation-key ordering.** Recommendation above is `[device, recovery, PDS]`
  (enclave supremacy). The alternative `[recovery, device, PDS]` favors the
  stolen-unlocked-device threat over the malicious-operator threat — worth one explicit
  ADR when this is scheduled, since it's near-impossible to change ergonomically later.
- **Release-delay default.** 24h? 0 for accounts with a confirmed second device? The
  delay's value depends on the notification relay existing; before push, cancel is
  email-only and the delay protects less.
- **Escrow release identity-proofing for email-less or unconfirmed-email accounts.**
  Mobile onboarding collects email, but nothing forces confirmation. Options: require
  confirmed email for escrow enrollment; fall back to operator-mediated release via the
  admin companion (signed-request audited).
- **k-of-n generalization.** The GF(2^8) core generalizes trivially, but 2-of-3 is
  hardcoded in `split_secret`'s signature and every holder story. Social-recovery-style
  n>3 (friends as holders) is attractive later; the share envelope's `set_id`/`index`
  design should not preclude it (1 byte of index allows 255 shares — fine).
- **Seed-derived vs independent recovery key for rotation ops.** Deriving via HKDF makes
  reconstruction verifiable against the DID doc with no extra stored state — chosen
  here. The cost: the seed *is* the key; share-set rotation is therefore also key
  rotation (a PLC op every time). That coupling seems right (rotating shares because
  some may be compromised should rotate the key), but worth confirming.
