# ADR-0030: A stable Keychain access group and a frozen iCloud container, both decoupled from the bundle id

- **Status:** Accepted
- **Date:** 2026-07-26
- **Deciders:** mal
- **Related:** MM-462; [MM-477](https://linear.app/malpercio/issue/MM-477) (the rename itself — blocked on this shipping and baking; carries the full coupling inventory and checklist); [MM-419](https://linear.app/malpercio/issue/MM-419) (notification keys need a shared group), [MM-451](https://linear.app/malpercio/issue/MM-451) (the iCloud backup is disaster-recovery input); `docs/design-plans/2026-07-24-wallet-identity-durability.md` §4; `apps/identity-wallet/src-tauri/{Entitlements.ios.plist,Info.ios.plist,src/keychain.rs}`; `scripts/bundle-identity-check.sh`

## Context

The wallet ships as Obsign. Its OAuth client is `identitywallet.obsign.org`, its redirect
scheme is `org.obsign.identitywallet`, and `Info.ios.plist` already carries a legacy
`dev.malpercio.identitywallet` URL-scheme entry beside the `org.obsign` one. The iOS bundle
identifier, however, is still `dev.malpercio.identitywallet`. A rename to `org.obsign.*` is
plainly contemplated, and reads as a one-line change to `tauri.conf.json`.

It is not one line. The bundle id silently doubles as two independent addressing schemes for
everything the user's identity depends on:

1. **The Keychain access group.** With no `keychain-access-groups` entitlement, every item
   lands in the implicit `$(AppIdentifierPrefix)<bundle-id>` group — the access group *is*
   the bundle id. Rename it and the device keys, Share 1, the per-DID sessions, and the
   managed-DID index are all still on disk and none are reachable.
2. **The iCloud container.** `iCloud.dev.malpercio.identitywallet` is hardcoded in
   `Entitlements.ios.plist` and in `Info.ios.plist`'s `NSUbiquitousContainers`. It holds the
   repo CAR snapshot and the blob mirror — the disaster-recovery source MM-451 rebuilds an
   account from, and the only backup layer that survives the PDS itself failing.

Both fail *silently*. There is no error and no degraded mode: the app comes up looking like a
clean install. A user who had not kept Share 3, and whose Share 1 lived only in the old access
group, would be unrecoverable through no action of their own.

This has not fired. The decision exists so that it cannot.

The second force is that **a bundle-id rename is not an update — it is a new app.** App Store
Connect treats the bundle id as immutable for an existing app record, so `org.obsign.*` means a
new record, a new App ID, and on-device a separate install rather than an upgrade in place.
That reframes both addressing schemes, and it does so asymmetrically:

- The **iCloud container** is addressed by a string we can declare on *both* App IDs. The same
  container id on the new App ID resolves to the same iCloud Drive files, wholly independent of
  what happens to the old install. It survives the app-identity change cleanly.
- The **Keychain** is stored per-install. `$(AppIdentifierPrefix)` expands to the *Team* id, not
  the bundle id, which is what lets a differently-named app on the same team read the old
  items at all — but only while those items still exist on the device. That holds if the new
  app is installed *before* the old one is deleted (the shared-access-group case working as
  designed). Otherwise it rests on iOS retaining Keychain items after an app is deleted, which
  is current behavior but something Apple has previously shipped a change to and reverted. That
  is not a footing for the device key.

The third force is timing, and it is now dated. Even a correct access-group change cannot ship
in the same release as the rename: a user who skips that version goes straight from "items in
the implicit legacy group" to "app that only knows the new group", which is the original
failure with extra steps. A **public TestFlight is imminent**, so the population that can be
stranded stops being hypothetical shortly. An iCloud container id, unlike an access group,
cannot be renamed at all — Apple offers no migration primitive, only the option of keeping a
container whose id does not match the bundle id.

Note what is *not* load-bearing here. An earlier reading justified the freeze mainly by user
harm — a user losing their backups through no action of their own. With a single user that
argument nearly evaporates: the container is `NSUbiquitousContainerIsDocumentScopePublic`, so
one person can migrate it by dragging a folder in Files.app. The decision does not rest on
that, and should not, because the property that makes it right is structural rather than
demographic.

## Decision

**We will decouple both addressing schemes from the bundle id, ahead of any rename, and freeze
the iCloud container id permanently.**

1. `Entitlements.ios.plist` declares `keychain-access-groups` explicitly, in this order:
   `$(AppIdentifierPrefix)org.obsign.shared` (stable) then
   `$(AppIdentifierPrefix)dev.malpercio.identitywallet` (legacy). Order is the mechanism: iOS
   files a new item into the **first** entitled group when a write names none, and searches
   **every** entitled group when a read names none. So writes land in the stable group and
   reads span stable-then-legacy without any call site naming a group.
2. No accessor in `keychain.rs` sets `kSecAttrAccessGroup`. Naming the group in Rust would
   require discovering the team's `AppIdentifierPrefix` at runtime, adding a failure mode to
   every Keychain call to re-implement a guarantee the OS already makes. The invariant that
   *is* enforced is the entitlement's shape, which no call site can observe: `keychain.rs`
   asserts it at compile time via `include_str!`, and `just bundle-identity-check` re-asserts
   it in CI.
3. The legacy group stays declared **indefinitely**. It is implicit only while the bundle id
   still matches it; the explicit entry is the sole thing keeping pre-rename items readable
   afterwards. An install that never updates never migrates, so there is no date at which
   dropping it becomes safe.
4. **The iCloud container id stays `iCloud.dev.malpercio.identitywallet` forever**, including
   after the rename, and the mismatch with the bundle id is documented rather than fixed. It is
   declared on both App IDs, which is what carries the mirrors across the app-identity change;
   the mismatch is cosmetic and invisible (the Files.app folder is named by
   `NSUbiquitousContainerName`, already "Obsign").
5. The rename may not ship until the access-group change has been in a released build for at
   least one full release cycle. `scripts/bundle-identity-check.sh` pins both apps' bundle ids
   so the rename cannot land as a one-line diff, and carries that checklist at its head.
6. **This change ships before the first public TestFlight build.** A tester who joins after it
   writes their identity material into the stable group from their first launch and never has
   a legacy-group-only install — which is the difference between a rename that has to migrate
   a population and one that only has to tolerate a shrinking tail. The window for making that
   true closes when public TestFlight opens, and does not reopen.
7. The rename, when it comes, must be sequenced as **install the new app before deleting the
   old**, because it is a new app record rather than an upgrade. This is a release-notes and
   onboarding obligation, not something the app can enforce; nothing may be built that depends
   on Keychain items outliving deletion of the old install.

## Consequences

- A bundle-id rename becomes survivable: keys and sessions written after this change are
  already in a group the rename does not touch, and items written before it stay readable
  through the explicit legacy entry.
- MM-419's notification keys get the shared access group they need; the plumbing lands once.
- The iCloud container id will visibly disagree with the bundle id after the rename. That is
  accepted untidiness with a documented reason: keeping it is what makes the mirrors survive
  the new app record, and it is the only one of the two schemes that survives it *without*
  depending on the old install's local state. (Secondarily: the mirrors are content-addressed
  and re-derivable from a live PDS, but the whole point of the disaster-recovery path is the
  case where no live PDS exists.)
- The two schemes now have different risk profiles under the rename, and that asymmetry should
  drive where future effort goes. The container is settled. The Keychain leg still depends on
  users installing the new app before deleting the old — so if the tail of legacy-group installs
  ever looks significant at rename time, the mitigation to reach for is a longer bake or an
  in-app prompt, not a container change.
- **No Apple Developer portal work and no profile regeneration are required.** Unlike the
  iCloud container, `keychain-access-groups` is not a registerable App ID capability: an App
  Store provisioning profile already authorizes the whole team prefix via a `<TeamID>.*`
  wildcard, so any group we name under it is covered — which is also why `org.obsign.shared`
  is usable while the bundle id is still `dev.malpercio.*`. Verified against the wallet's
  current App Store profile on 2026-07-26; re-check after any profile change with:

  ```
  security cms -D -i <profile>.mobileprovision | plutil -p - | grep -A3 keychain-access-groups
  ```

  The team prefix is therefore doing double duty — it is both the authorization boundary and
  the addressing prefix. That is the property the whole design rests on.
- A rename now requires a deliberate edit to the gate's pins in the same PR. That is friction
  by design; the gate's header is where the migration checklist lives.
- Entitlement order is now load-bearing in a way that reads as cosmetic. Two independent
  checks (a Rust test and a shell gate) exist because a reviewer cannot be expected to know
  that reordering an array orphans identity material.

## Alternatives considered

**Rename the bundle id and accept the loss.** Rejected outright: the loss is total, silent, and
falls on users who did nothing wrong.

**Set `kSecAttrAccessGroup` explicitly on every read and write.** This is what the issue's
definition of done literally describes, and it is more self-documenting. Rejected because the
literal group string requires the team's `AppIdentifierPrefix`, which is only discoverable at
runtime (a probe write plus an attribute read) — introducing a new failure mode into the path
that stores Share 1, in order to reproduce a default the OS already applies deterministically.
The entitlement-order mechanism achieves the same read/write behavior; the enforcement moved
into a compile-time test rather than into the hot path.

**Derive the legacy group from the current bundle id rather than pinning it.** Rejected: it
would make a rename self-consistent, silently redefining "legacy" to mean the *new* bundle id
and orphaning exactly the items the entry exists to protect.

**Ship a one-time copy from the old iCloud container to a new `iCloud.org.obsign.*` one, keeping
the old until verified.** Rejected. It is strictly more machinery than keeping the container id,
and it runs at the worst possible moment — during a transition that is already creating a new
app record, in a window where the copy can be interrupted by the user deleting the old app or
going offline. It buys only that the container id matches the bundle id, a string Apple
explicitly permits to differ and which no user ever sees. Note this was *feasible* while there
was one user, who could migrate by hand in Files.app; it stops being feasible the moment a
public TestFlight opens, which is why the decision is taken now rather than deferred.

**Rely on the entitlement alone and skip the CI gate.** Rejected: the rename still reads as a
one-line diff to a reviewer, and the entitlement's array order — the actual mechanism — is
exactly the kind of detail a tidy-up PR reorders without noticing.
