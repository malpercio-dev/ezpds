# Shared iOS Swift sources

Last verified: 2026-08-19

## Purpose

Swift that belongs to the iOS apps but to neither app's Rust crate. Today that is exactly one
thing: the **Notification Service Extension**, which unseals encrypted push notifications on
arrival — compiled into BOTH apps' projects (the wallet's user notifications and the operator
console's ops alerts) from this one source tree.

It sits at the repo root rather than under `apps/identity-wallet/` for the same reason
`scripts/ios/` does — the XcodeGen template that compiles it is shared by both apps, so its
inputs are shared too. Which app's keychain items an extension reads is decided at render
time: the template sets the per-app service name in the extension's Info.plist
(`EzpdsKeychainService`), which `NotifyKeychain.swift` resolves at runtime.

## Contracts

### `NotificationService/` — the extension (`{{app.name}}_NSE`)

**Exposes:** `NotificationService`, a `UNNotificationServiceExtension` subclass iOS
instantiates via `NSExtensionPrincipalClass` when a push carries `mutable-content: 1`.

**Guarantees:**
- A payload that opens under HPKE Auth mode renders as content. **Everything else renders as
  the explicit unverified notice** — never a guess, never a partial render, never the relay's
  placeholder passed through as though it were news. This is the extension's single rule, and
  it holds on the timeout path too (`serviceExtensionTimeWillExpire`).
- The sealed `ezpds` block is stripped from the delivered notification, so ciphertext never
  reaches the app's delivered-notification list.
- A **verified** payload's routing identifiers survive into the delivered notification as the
  `ezpdsRoute` `userInfo` block (`{type, requestId?, did?}` — an allowlist read from the
  payload's `data`, never a passthrough). It is written only on the rendered path, so its
  presence in a delivered notification is itself the "HPKE Auth vouched for this" statement the
  app's tap handler relies on to deep-link (the wallet still re-fetches everything it displays
  from the server by `requestId`). An unverified or timed-out delivery never carries it.
- Every failure leaves a breadcrumb in the shared Keychain, best effort. A Keychain that will
  not take a diagnostic never costs the user the notice itself.

**Expects:**
- `keychain-access-groups` listing the host app's stable group **first** (wallet:
  `$(AppIdentifierPrefix)org.obsign.shared` in its `Entitlements.NSE.plist`; console:
  `$(AppIdentifierPrefix)org.obsign.admin.shared` in its own — the groups are deliberately
  distinct so neither extension can read the other app's keys). Nothing here names an access
  group in a query — naming one would mean discovering `AppIdentifierPrefix` at runtime, on
  the one code path that must work on a locked screen — so the entitlement's *order* is the
  mechanism.
- The host app having registered: `notification-key-priv` and `notification-sender-keys`,
  both under `kSecAttrAccessibleAfterFirstUnlock`, written by that app's `notifications.rs`
  under its own keychain service (named by the extension's `EzpdsKeychainService` Info key;
  absent, the wallet's service — so a pre-key wallet extension behaves identically).
- iOS 17. `HPKE.Recipient`'s auth-mode initializer does not exist before it.

| File | What it holds |
|---|---|
| `NotificationService.swift` | The `UNNotificationServiceExtension` shell, plus `NotifyResolver` — the pure failure ladder every branch of which is a banner someone reads — and `NotifyTimeout`, the pure timeout-path decision split out for the same testability reason (the sealed block's presence, not the title, is the "resolution was cut short" signal), so a timed-out push records its breadcrumb instead of leaving Settings reporting a clean bill of health under a "couldn't verify" banner |
| `NotifyCrypto.swift` | CryptoKit `HPKE.Recipient` in auth mode, suite/`info`/`aad` pinned to `crates/crypto/src/hpke.rs` |
| `NotifyEnvelope.swift` | Envelope + payload parsing, base64url, `did:key` → SEC1, base58 |
| `NotifyKeychain.swift` | The shared-Keychain reads, and the pin document's shape |
| `NotifyBreadcrumbs.swift` | The bounded failure log the app surfaces in Settings |

### `NotificationServiceTests/` — the logic-test bundle (`{{app.name}}_NSETests`)

Compiled with the extension's sources rather than linking them: an app extension has no
testable module to import, since there is no `TEST_HOST` an extension can be loaded into.

`NotifyFixtureTests` is the **cross-implementation check** — it opens
`crates/crypto/tests/fixtures/notify/hpke-notify-v1.json` (sealed by Rust's `hpke` crate) with
CryptoKit. RFC 9180's appendix carries no vector for this suite, so nothing else proves the two
agree on the pinned suite, the `info` string, the empty `aad`, and the key encodings. The
fixture is referenced **in place** by the template — there is no copy here to drift.

## Dependencies

System frameworks only: CryptoKit, Foundation, Security, UserNotifications. Deliberately no
Swift package dependency — a package in the extension is a second supply chain in the one
process that runs on a locked screen.

## Key Decisions

- **Swift, not a second Rust staticlib.** Decryption is ~200 lines of CryptoKit; a second
  staticlib would double the iOS build's slowest step for it.
- **Breadcrumbs go to the shared Keychain, not an app-group container.** The keychain group is
  already entitled and needs no Apple Developer portal work; an app group would be a second new
  entitlement on both bundles. The cost is that a push arriving before the first unlock after a
  reboot leaves no breadcrumb — the one failure that repairs itself, and the least worth
  recording.
- **The extension is gated to an explicit two-app allowlist** in `scripts/ios/project.yml`
  (both bundle ids since the console's notification adoption). An app extension is a separate
  bundle needing its own App ID, profile, and signing secret per app — a third app would be
  added deliberately, together with its keychain group and those artifacts.

## Invariants

- The Keychain account names and both JSON document shapes in `NotifyKeychain.swift` /
  `NotifyBreadcrumbs.swift` are **copies** of constants in each app's
  `src-tauri/src/{keychain,notifications}.rs` (both apps spell the same account names; the
  per-app *service* name arrives via `EzpdsKeychainService`). Separate bundles can only
  agree by both spelling the same strings; a rename on one side is silent on the other.
- `PRODUCT_MODULE_NAME` is pinned to `NotificationService` in the template. It is half of
  `NSExtensionPrincipalClass`, so a drift leaves iOS unable to instantiate the extension — a
  failure indistinguishable from a push that never arrived. `just ios-check` greps the pbxproj
  for it.
- The failure `reason` vocabulary (`NotifyFailureReason`) is shared with the app's
  `NotificationFailure.reason` and the frontend's `NotificationFailureReason`. Both readers
  tolerate an unrecognized value on purpose: the extension versions independently, and the entry
  a strict reader would drop is the one the user is asking about. A new case still needs wording
  in `apps/identity-wallet/src/lib/notification-health.ts`.
- CI gates, in order of what they can catch:
  - `just _nse-typecheck` (macOS, part of `just ios-pr-check`) — `swiftc -typecheck` of the
    extension's sources, then of the test bundle exactly as the template composes it, against
    the real iOS SDK at the deployment target both apps declare. No simulator, no signing, no
    generated Xcode project. This is the only thing that compiles this Swift before a release
    archive would.
  - `just ios-template-check` (Linux) — target present, gated to the wallet, embedded,
    principal class and module name, entitlements order and least privilege, sources exist.
  - `just ios-check` (macOS) — the same structural facts in the generated pbxproj.
  Nothing *runs* the tests in CI: `ios-pr-check` performs no `xcodebuild`, so the fixture
  cross-check is a local `xcodebuild test -scheme <app>_NSETests` (or `⌘U` on that scheme).
