# Wallet Identity Durability — Reinstall, Restore, and Redistribution

**Status: landed.** All three fixes shipped — MM-460 (§2, PR #426), MM-461 (§3, PR #448),
MM-462 (§4, PR #445). §5's cross-references are handoffs to work tracked elsewhere, not
open items of this plan.

Three defects in the wallet's local-persistence layer, found by auditing what actually
survives when the app's *installation* changes rather than when the *network* fails.
Each is small in code and large in consequence: the first
means the recovery model is one share weaker than designed, the second means the wallet
can claim custody it does not have, the third is a loaded footgun that has not fired yet.

This plan also writes down the thing that did not previously exist in one place: a
**durability matrix** stating, for every way an install can end, exactly what survives
and which recovery path applies. §1 is that matrix; §§2–4 are the three fixes; §5 maps
the seams to work already tracked elsewhere.

## Summary

The wallet's identity material lives in the iOS Keychain under service
`ezpds-identity-wallet` (`keychain.rs`), plus two iCloud Drive mirrors (repo CAR + blobs)
in the ubiquity container. The network side — the did:plc document, its audit log, and
the escrowed Share 2 — is never at risk from anything on this page; the question is only
ever *what does the device still hold, and can the user get back to authority over their
DID*.

Three findings:

1. **Share 1 is not iCloud-synced.** Every Keychain write goes through
   `security_framework::passwords::set_generic_password`, whose `PasswordOptions::new_generic_password`
   sets exactly `kSecClass` / `kSecAttrService` / `kSecAttrAccount` — no
   `kSecAttrSynchronizable`. Nothing in the repo sets it. So Share 1 stays on one device,
   while the design plan, the UI copy, the user docs, and even
   `rekey.rs`'s own doc comment ("durable, iCloud-synced Share 1") all state that it syncs.
   The escrow-assisted recovery path is specified as *Share 1 (iCloud) + Share 2 (escrow)*
   with no user-held secret required; as built, that path needs Share 3 — the one thing the
   user might not have kept.

2. **A restored install can report a rotation key it cannot use.** On real devices the
   device key is Secure-Enclave-backed: the private key never leaves the enclave and its
   two metadata items (`{did}:device-key-pub`, `{did}:device-key-app-label`) are ordinary
   generic passwords. Those metadata items are restorable from an encrypted device backup;
   the enclave key is not. `get_or_create_per_did_device_key`'s fast path
   (`identity_store.rs:604-623`) sees both metadata items and returns the cached public key
   *without touching the enclave*, so the identity renders with a valid "root key" badge —
   and then every signing attempt dies at `per_did_sign_closure`'s "SE key not found"
   (`identity_store.rs:805`). The user is told they hold `rotationKeys[0]` while nothing
   they do can sign.

3. **A bundle-ID rename would silently destroy every install.** No
   `keychain-access-groups` entitlement is declared, so items land in the implicit group
   `$(AppIdentifierPrefix)dev.malpercio.identitywallet`. The product is branded Obsign, the
   OAuth client is `org.obsign.identitywallet`, and `Info.ios.plist` already carries a
   legacy `dev.malpercio.identitywallet` URL-scheme entry beside the `org.obsign` one — a
   rename is clearly contemplated. Renaming the bundle ID changes the Keychain access group
   *and* the iCloud container ID at once. Every existing install would update into an app
   that cannot see its own keys or its own backups, with no error and no recovery path
   short of the share ceremony.

None of the three is a protocol or server concern. All three are wallet-local.

## 1. The durability matrix

### 1.1 What holds an identity

| Material | Keychain account | Survives reinstall? | Survives new device? |
|---|---|---|---|
| Managed DID index | `managed-dids` | No | No |
| Device key — software (sim/macOS) | `{did}:device-key` | No | Encrypted local backup only |
| Device key — Secure Enclave (real device) | SE key + `{did}:device-key-pub`, `{did}:device-key-app-label` | No | **Never** (enclave-bound) |
| Shamir Share 1 | `recovery-share-1:{did}` | No (should be: yes, via iCloud Keychain) | No (should be: yes) |
| Full-access session | `{did}:oauth-tokens` | No | No (and must not) |
| DR signing key | `{did}:recovery-signing-key` | No | No (and must not) |
| Cached DID doc / PLC log | `{did}:did-doc`, `{did}:plc-log` | No | No (re-fetchable) |
| Ceremony / epilogue staging | `ceremony-staging`, `recovery-epilogue` | No | No (and must not) |
| Repo CAR + blob mirror | iCloud Drive ubiquity container | **Yes** | **Yes** |
| DID doc, audit log, Share 2 escrow | not local | **Yes** | **Yes** |

Two platform rules drive every row. First, since iOS 10.3 an app's private-access-group
Keychain items are deleted with the app, so "uninstall" means "wipe". Second, a Keychain
item reaches a *different* device by exactly two routes: `kSecAttrSynchronizable` (live
iCloud Keychain sync) or an encrypted Finder/iTunes backup — an iCloud Backup re-encrypts
the keychain to the device UID and restores only to the same device. The wallet uses
neither route today, which is finding 1.

### 1.2 Scenario matrix

| Scenario | What survives | Path back |
|---|---|---|
| App update (TestFlight internal → external → App Store) | Everything | None needed |
| Delete + reinstall | iCloud Drive mirrors, network state | Recovery ceremony |
| Restore to new device from encrypted backup | Mirrors, network state, non-SE Keychain items | Recovery ceremony — **today misreports as healthy** (finding 2) |
| Restore to new device from iCloud Backup | Mirrors, network state | Recovery ceremony |
| Planned switch, both devices in hand | Everything (old device signs the handover) | MM-425 — no shares, no wait |
| Lost/dead device, iCloud intact | Mirrors, network state, **Share 1 once finding 1 is fixed** | Escrow-assisted recovery (Share 1 + Share 2) |
| Lost device, escrow unavailable or distrusted | Mirrors, network state | Sovereign recovery (Share 1 + Share 3), fully offline |
| PDS gone/hostile | Mirrors, keys, network state | Disaster recovery (MM-451) |
| Bundle-ID rename | Nothing reachable | **None** — finding 3 |

The recovery ceremony (`share_recovery.rs`) already handles every "wipe" row correctly by
design: it reconstructs the recovery key from any 2 of 3 shares, mints a *fresh* per-DID
device key, and rotates it into `rotationKeys[0]`. Enclave keys being non-portable is not
a gap — it is the premise the ceremony was built on. The gaps are that one of the three
shares is not where it was designed to be, and that one scenario lies about its state
instead of routing into the ceremony.

## 2. Phase 1 — make Share 1 actually sync (MM-460)

**Goal:** `recovery-share-1:{did}` reaches the user's other Apple devices and a fresh
install on a new phone, so escrow-assisted recovery works as specified with no user-held
secret.

### 2.1 The change

Add an options-taking write path to `keychain.rs` beside the existing `store_item`, and
use it *only* for Share 1:

```rust
/// Store bytes that must follow the user's Apple account rather than the device.
/// Synchronizable items reach the user's other devices via iCloud Keychain and a
/// fresh install after a restore; the default `store_item` deliberately does not.
pub fn store_item_synced(account: &str, data: &[u8]) -> Result<(), KeychainError>;
pub fn get_item_synced(account: &str) -> Result<Vec<u8>, KeychainError>;
pub fn delete_item_synced(account: &str) -> Result<(), KeychainError>;
```

built on `set_generic_password_options` / `generic_password(PasswordOptions)` with
`kSecAttrSynchronizable = true`. Synchronizable and non-synchronizable items with the same
service+account are **distinct records**. Apple's `SecItem.h` is explicit:

> To add a new item which can be synced to other devices, or to obtain synchronizable
> results from a query, supply this key with a value of `kCFBooleanTrue`. If the key is
> not supplied, or has a value of `kCFBooleanFalse`, then no synchronizable items will be
> added or returned.

So a synced write does not update a legacy non-synced item, and a default-query read will
never find a synced item. That makes the read path a two-step (synced first, then legacy)
and the backfill explicit; see §2.3.

Accessibility stays at the framework default (`kSecAttrAccessibleWhenUnlocked`).
`…ThisDeviceOnly` is mutually exclusive with syncing, and Share 1 must be readable
during an unattended recovery attempt, so no `…AfterFirstUnlock` gymnastics are needed.

### 2.2 What must *not* sync

This is the security half of the phase and belongs in the code comments, not just here:

- **Device key** (`{did}:device-key` software scalar) — must never sync. The whole
  security argument for `rotationKeys[0]` is that it is enclave-bound on a real device;
  syncing the simulator/macOS fallback scalar would make the dev path strictly weaker than
  the production path it stands in for.
- **`{did}:oauth-tokens`** — a live full-access session must not appear on a device the
  user has not authenticated on.
- **`{did}:recovery-signing-key`** — the offline service-auth minting key.
- **`ceremony-staging` / `recovery-epilogue`** — in-flight state whose whole contract is
  fail-closed single-device ownership. Two devices resuming one epilogue is a
  correctness hazard, not a convenience.
- **Everything else** — no reason, so no.

Share 1 syncing is safe precisely because it is one share of a 2-of-3: an attacker with
the Apple account gets one share and still needs escrow release (which is OTP-gated with
a 24h delay and cancellable) or the user's Share 3. That is the threat model ADR-0027
already argues, with the device key's 72-hour override supremacy as backstop.

### 2.3 Backfill for existing installs

`lib.rs` already runs a best-effort startup migration for the pre-unification global
`recovery-share-1` slot (`migrate_global_share1_to_per_did`). Extend the same launch step:
for every managed DID, if the *synced* slot is absent and the *legacy non-synced* slot
holds a valid v2 envelope, write it to the synced slot. Additive, idempotent, never
deletes the legacy slot — same discipline as the existing migration, for the same reason
(the legacy slot may be the only copy).

Recovery's auto-load (`start_share_recovery`) then reads synced → per-DID legacy →
global legacy, in that order.

**Copy, never flip in place.** `SecItem.h` documents `kSecAttrSynchronizable` for
*targeting* synced items during update/delete ("Updating or deleting items using the
`kSecAttrSynchronizable` key will affect all copies of the item, not just the one on your
local device") but does **not** document changing an existing item's synchronizability in
place. Treat an in-place flip as unsupported. Copying is the safer construction regardless:
the legacy slot may be the only surviving copy of that share, so the migration must never
mutate or delete it.

### 2.3.1 What the backfill cannot reach

The backfill runs on-device, so it only reaches a device that **both** still holds Share 1
**and** launches the fixed build at least once. Three consequences, none of which the fix
can engineer away:

- **Users who have already lost their device are not helped.** This change cannot reach
  backward; those accounts remain on Share 2 + Share 3 for the life of the identity. MM-460
  protects the installed base from the moment they update, not the existing casualties. Any
  user-facing framing of the fix has to say that plainly rather than implying a retroactive
  repair.
- **A user who updates and opens the app is protected silently** from that launch onward,
  with no action required of them.
- **iCloud Keychain must be enabled on the account.** With it off, the item is written
  carrying the attribute and propagates nowhere; enabling it later syncs the item with no
  further app involvement.

The last point is the sharp edge behind §2.4: "we wrote it with the sync flag set" and "it
reached your Apple account" are different claims, and the app can only ever verify the
first. That gap is a copy problem, not a code problem — but it is the difference between a
user who thinks they are covered and one who is.

### 2.4 Honest sync status

`docs/mobile-architecture-spec.md:486` specifies "App verifies sync success, warns if
failed" — never built, and the UI currently asserts success unconditionally
(`ShamirBackupScreen.svelte:91`: "Saved to iCloud Keychain automatically").

iOS exposes no "has this item synced" callback, so do not fake one. What *is* knowable and
worth surfacing: whether iCloud Keychain is enabled for the account at all. Where that
cannot be determined, the copy must degrade to a claim we can defend — "Saved to your
Keychain, and to iCloud Keychain if enabled" — rather than a promise we cannot verify.
Share 3's "write this down" step stays non-skippable regardless; it is the only share
whose durability does not depend on a vendor.

### 2.5 Definition of done

- Share 1 written with `kSecAttrSynchronizable`; read path prefers the synced slot.
- No other account gains the flag; a unit test asserts the deny-list explicitly.
- Launch backfill copies legacy → synced, idempotently, without deleting legacy.
- UI/doc copy matches what the code guarantees (`ShamirBackupScreen`, `RecoverStartScreen`,
  `sites/docs/.../user/backup.md`, `.../user/screens.md`, and `rekey.rs`'s doc comment).
- Device-verified: onboard on device A, confirm Share 1 auto-loads into recovery on
  device B signed into the same Apple account.

## 3. Phase 2 — Secure Enclave liveness probe (MM-461)

**Goal:** the wallet never reports custody of a rotation key the enclave cannot sign with.

### 3.1 The change

In the SE branch of `get_or_create_per_did_device_key`, the fast path currently treats
"both metadata items present" as proof of key existence. Add a liveness check: resolve the
stored `application_label` against the enclave (the same `ItemSearchOptions` lookup
`per_did_sign_closure` performs) and confirm a key reference comes back.

Three outcomes:

- **Key resolves** → return the cached public key, unchanged behavior.
- **Metadata present, key absent** → this DID's device key is gone. Do **not** silently
  mint a fresh key: a new key is not in the DID's `rotationKeys` and would make the "root
  key" badge wrong in the opposite direction. Return a distinct
  `IdentityStoreError::DeviceKeyUnusable` so callers can route the identity into recovery.
- **Metadata absent** → generate, as today.

The probe is a Keychain query, not a signing operation, so it triggers no biometric prompt
and costs a lookup on the first call per DID per launch. Cache the verdict in-process to
keep the fast path fast.

### 3.2 Surfacing it

`IdentityListHome` / `DIDDocumentScreen` currently derive the root-key badge from
`getDeviceKeyId`. With `DEVICE_KEY_UNUSABLE` they should render an explicit "This device
can no longer sign for this identity — recover to restore control" state and offer the
recovery ceremony, which is exactly the right destination: it mints a fresh SE key and
rotates it into `rotationKeys[0]`.

This is the same honesty rule the rest of the wallet follows — status never by color
alone, never a claim the code cannot back.

### 3.3 Definition of done

- Fast path verifies enclave residency before reporting a key.
- New `DEVICE_KEY_UNUSABLE` variant plumbed through `IdentityStoreError` → `$lib/ipc`.
- Frontend renders the degraded state and routes to recovery.
- Unit test: metadata present + enclave lookup miss ⇒ `DeviceKeyUnusable`, not a
  freshly-minted key and not a success.

## 4. Phase 3 — bundle-ID rename safety net (MM-462)

**Goal:** make the `dev.malpercio.*` → `org.obsign.*` rename survivable, and make it
impossible to perform accidentally before the net is in place.

### 4.1 Why it is not just a string

Renaming the bundle ID changes two independent addressing schemes at once:

1. **Keychain access group** — implicit today, so it *is* the bundle ID. New group ⇒ every
   existing item invisible.
2. **iCloud container** — `iCloud.dev.malpercio.identitywallet`, hardcoded in
   `Entitlements.ios.plist` and `Info.ios.plist`'s `NSUbiquitousContainers`. New container
   ⇒ the repo CAR and blob mirror are gone too.

Both fail *silently*: the app comes up looking like a fresh install. A user who had not
kept Share 3 and whose Share 1 lived only on the old bundle ID's access group would be
unrecoverable through no action of their own.

### 4.2 The net

**Step 1 — decouple the access group from the bundle ID, now, ahead of any rename.**
Declare an explicit `keychain-access-groups` entitlement naming a stable group that does
not track the bundle ID, and have `keychain.rs` write to it. This is worth doing on its
own merits: MM-419 (notification keys) already needs a shared access group, so the
plumbing lands once.

The ordering constraint is absolute: the app must **read from both** groups and **write to
the new** one for at least one full release cycle before the bundle ID moves. A rename
shipped in the same release as the group change strands anyone who skips that version.

**Step 2 — container migration.** An iCloud container ID cannot be renamed. Either keep
the existing container ID after the bundle rename (Apple allows a container whose ID does
not match the bundle ID, which is the cheap answer), or ship a one-time copy from old to
new with the old kept until verified. Recommendation: keep the existing container ID and
document why it does not match the bundle ID — the mirrors are content-addressed and
re-derivable, but a silent loss of the disaster-recovery source is not worth the tidiness.

**Step 3 — a gate that fails the build.** Add a check to `just ci` asserting that the
bundle identifier in both apps' `tauri.conf.json` matches the entitlements' container ID
expectations and the declared access group, so a rename cannot land as a one-line diff
without the migration.

### 4.3 Definition of done

- Explicit `keychain-access-groups` entitlement; `keychain.rs` writes to the stable group,
  reads from stable-then-legacy.
- Documented, enforced ordering: group change ships and bakes before any rename.
- Container decision recorded in an ADR (it outlives this plan and constrains future
  bundle work).
- CI gate rejecting a bundle-ID change that is not accompanied by the migration.

## 5. Seam with existing work

This plan deliberately covers only the *local persistence* layer. The identity-authority
flows it hands off to already exist or are already tracked:

- **MM-425 — planned device switch** (both devices in hand). The old device's key signs a
  rotation op installing the new device's key at `rotationKeys[0]`; no shares, no contest
  window. §1.2's "planned switch" row is that issue's, not this plan's. Phase 2 is
  complementary: it is what should happen when a switch *was not* planned.
- **MM-410 — recovery ceremony.** Every "wipe" row in §1.2 terminates here. Phase 1 is what
  makes its escrow-assisted path work as specified.
- **MM-451 — sovereign disaster recovery.** The "PDS gone" row; orthogonal to everything
  here (it assumes local keys are intact).
- **ADR-0027 — rotation-key ordering.** The `[device, recovery, PDS]` layout and the
  72-hour override supremacy are the reason Phase 1's synced share is safe.

## 6. Risks and open questions

- **Does syncing Share 1 widen the blast radius of an Apple-account compromise?** It moves
  Share 1 from "one device" to "the user's Apple account", which is the *designed*
  position (ADR-0001, ADR-0027) and is still one share short of the threshold. The escrow
  release gate and the device key's override window are what carry the risk. Worth an
  explicit re-affirmation in review rather than an assumption.
- **Users with iCloud Keychain disabled** get no Share 1 portability at all. The honest-copy
  work in §2.4 is what keeps that from being a silent surprise; Share 3 remains their real
  backup.
- **Should the probe in Phase 2 auto-route into recovery, or wait for the user?** Leaning
  wait-and-offer: an automatic ceremony launch on app open would be alarming, and the
  identity is not in danger — only this device's control of it is.
- **Is there a second device story beyond replace-and-retire?** PLC allows five rotation
  keys and the current layout spends three. MM-425 already flags "replace vs. add" as open;
  Phase 1's synced share does not foreclose either.
