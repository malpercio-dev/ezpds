# Obsign (identity-wallet) Mobile App

Last verified: 2026-08-02

## Purpose

Tauri v2 iOS application — SvelteKit 2 + Svelte 5 frontend running in a native WKWebView,
communicating with a Rust backend exclusively through Tauri's IPC bridge.

This file is a map. Each entry is what the module is plus the fact or two an agent needs
before opening it; mechanism and invariants live in the module's own doc comment
(`//!` in Rust, the header comment in TS/Svelte).

## Browser test harness (drive the app without a simulator)

The frontend runs in a desktop browser under `vite dev`; the harness intercepts the one
missing seam — Tauri `invoke()` — with the official `mockIPC`, so an agent can reach every
screen and reproduce any state without a Mac/Xcode/simulator. Design + ACs:
[docs/archive/design-plans/2026-07-12-browser-harness.md](../../docs/archive/design-plans/2026-07-12-browser-harness.md).

- **Start** (or the `.claude/launch.json` configs `wallet-harness` / `wallet-harness-proxy`):
  fake mode `pnpm --dir apps/identity-wallet dev:harness` → http://localhost:5173; proxy mode
  `cargo build -p pds` + `just harness-pds` (prints URL + token), then
  `VITE_HARNESS_PDS_URL=<url> VITE_HARNESS_ADMIN_TOKEN=<token> pnpm --dir apps/identity-wallet dev:harness:proxy`.
- **`window.__harness` console API**: `.scenario(name)` switches preset and reloads
  (`.scenarios` lists them; each preset's purpose — including which states only it can
  reach — is a doc comment in `src/lib/harness/scenarios.ts`), `.failNext(command, error)`,
  `.emit(event, payload)`, `.state()` (a deep-cloned snapshot, never the live store), `.mode`.
- **Proxy mode is real only for the thin-HTTP subset** (`create_account`,
  `get_available_user_domains`); the honest fake-vs-real boundary and the device-only
  fidelity list are documented in `src/lib/harness/proxy/index.ts` and `install.ts`.
- Double-gated on `import.meta.env.DEV && VITE_HARNESS` (plain `pnpm dev` never activates
  it); `pnpm check:harness-absence` proves production tree-shaking; `registry.test.ts` fails
  if a `$lib/ipc` command lacks a fake handler. Code: `src/lib/harness/`, activated by
  `src/hooks.client.ts`.

## Contracts

### Frontend (SvelteKit 2 + Svelte 5)

- `src/lib/ipc/` — per-domain typed `invoke()` wrappers re-exported from `index.ts`; page
  components import from `$lib/ipc` and never call `invoke()` directly. The rule and its two
  policy-gate exceptions (`$lib/biometric`, `$lib/unlock`) are stated in `index.ts`'s header;
  the per-domain modules are the authority on what is exported. `qr-scan.ts` is the
  mobile-only barcode-scanner binding, dynamically imported (off-device the scan rejects and
  screens fall back to typed-code entry).
- `src/lib/components/onboarding/` — one screen component per step of the create / import /
  recover flows (the directory listing is the authoritative inventory). The two source-PDS
  password logins (`PdsAuthScreen`, `MigrationSourceAuthScreen`) are thin wrappers over one
  shared `SourcePasswordAuthScreen` base.
- `src/lib/components/home/` — the home-surface screens plus DIDAvatar (the directory
  listing is the authoritative inventory; each screen's role, entry point, and rules are its
  top-of-file comment). ProtectionScreen is the app-level Defend surface (shared derivations
  in `$lib/protection` keep it and the home strip from contradicting each other);
  IdentityScreen is the per-identity instrument panel — state leads, actions follow — with
  the Use zone (consent approval / app passwords / agents) and two doors: MoveOrRebuildScreen
  (the exit) and ManageIdentityScreen (maintenance), with AdvancedToolsScreen as the
  vestibule behind the latter.
- `src/routes/+page.svelte` — the root page and the app's whole step machine: the create /
  import (claim) / recover flows from the `add_identity` situation question, the home tier,
  the alarm-takeover landing, and the launch reconciliation ordering. The full step graph
  and gate rules are the HTML comment at the top of the file; takeover/dismissal semantics
  live on the `shownAlarms`/`landOnAlarm`/`goTo` doc comments, the multi-entry back-path
  rules on the `alertReturnStep`/`identityReturnStep` declarations, and the
  situation-question rationale on AddIdentityScreen.
- Utilities (each file's header carries its rules):
  - `src/lib/appearance.ts` — System/Light/Dark override; Keychain is truth, localStorage mirror is pre-paint only
  - `src/lib/agent-scopes.ts` — plain-language OAuth scope descriptions; elevated flags + unknown-token honesty rule
  - `src/lib/deadline.ts` — 72h PLC recovery-window math (`getDeadline`/`getUrgency`/`formatCountdown`)
  - `src/lib/identity-status.ts` — identity panel state derivation; panel-vs-badge `safe` and the load-bearing did:web `isVerified` short-circuit
  - `src/lib/protection.ts` — shared Defend derivations; ordering-vs-`activeStrip` rule, worst-state-wins summary
  - `src/lib/alarm-landing.ts` — pure launch/foreground alarm-landing decision (`decideAlarmLanding`, `alarmKey`)
  - `src/lib/identity-cards.ts` — `loadIdentityCard(s)` local facts; `degraded`-flag semantics
  - `src/lib/unlock.ts` — `unlockIdentity`, the one sovereign-vs-password unlock gate; inverted-dialog design, `UNLOCK_CANCELLED` is a decision not a fault
  - `src/lib/biometric.ts` — `authenticateBiometric`, the fail-closed user-presence gate before irreversible signing
  - `src/lib/notification-health.ts` — folds NSE failure breadcrumbs into one Settings sentence; two-level severity rules
  - `src/lib/consent-qr.ts` — pure `parseConsentQr`; ignores the QR's origin (the server re-verifies by `request_id`)
  - `src/lib/claim-errors.ts` — shared RATE_LIMITED / SERVER_ERROR message formatting

**Guarantees:** SSR is disabled globally (`ssr = false` in `src/routes/+layout.ts`) — the
frontend is a static SPA loaded from disk by WKWebView, with build output in `dist/`
(`pages: 'dist'` in `svelte.config.js`, matching `tauri.conf.json`'s `frontendDist`). PDS
error codes map back to the originating screen (e.g. EXPIRED_CODE → claim_code step).

**Expects:** `pnpm install` has been run in `apps/identity-wallet/`; Node.js 22.x in PATH
(provided by the Nix dev shell).

### Rust Backend (src-tauri/)

One module per concern; each module's `//!` doc is the authority on its commands, errors,
and invariants. **Wire contract (every module):** IPC error enums serialize as
`{ code: "SCREAMING_SNAKE_CASE" }` with camelCase payload fields, and IPC types serialize
`#[serde(rename_all = "camelCase")]`; the TypeScript unions/types in `$lib/ipc` must match
exactly. Which variants exist, what they carry, and which reach the frontend: the module doc.
The typed error is also the user-facing seam
([ADR-0031](../../docs/architecture/decisions/0031-user-facing-error-seam.md)): screens own
the sentence keyed on `code`; a `message` field is diagnostic only unless its doc comment
declares it server-quoted. Diagnostic ≠ unrenderable — it may never appear *inside* the
user's sentence, but a screen may carry it in a visually subordinate, explicitly-diagnostic
detail slot (the MigrationProgressScreen pattern). Only declared server-quoted text may
render behind server attribution, and then only length-bounded.

**Seven strict pre-sign guards** protect every wallet-signed PLC op; each guard's full
allowlist lives in its module's doc — `claim.rs` (the 4-point claim verification),
`migrate.rs`, `handle_change.rs`, `rotate_repo_key.rs`, `disaster_recovery.rs`,
`endpoint_repair.rs`, `self_held_kit.rs`.

| Module (src-tauri/src/) | What it is |
|---|---|
| `lib.rs` | crate root and app wiring: the cross-cutting IPC commands (account creation, both DID ceremonies, PDS config/capabilities, IdentityStore reads, appearance) plus `run()`'s startup sequence — see module doc |
| `main.rs` | desktop entry point (calls `lib::run()`) |
| `keychain.rs` | the two Keychain stores (device-local + iCloud-synchronizable, allowlist-gated), protection classes, the access-group entitlement invariant, and the **canonical account inventory** — the module doc is the authority on every account name |
| `device_key.rs` | the global P-256 device key, software-or-Secure-Enclave by `#[cfg]`; `get_or_create` idempotent, `sign` low-S-normalized r\|\|s — see module doc |
| `identity_store.rs` | multi-identity Keychain lifecycle (`managed-dids` index + per-DID entries), lazy per-DID device keys with the Secure-Enclave liveness probe, the shared `SovereignTokenRecord` session record; removal semantics and the Share 1 exception in the module doc |
| `share_ceremony.rs` | client-side 2-of-3 share generation + the three fail-closed staging slots (create / re-key / self-held kit); staging contract and load-bearing teardown order in the module doc |
| `share_recovery.rs` | the "Recover existing identity" ceremony (10 IPC commands) and its resumable rotation epilogue — see module doc |
| `rekey.rs` | additive-only re-key of pre-inversion `[device, PDS]` accounts onto the client-share model; owns the per-DID Share 1 slot (`recovery-share-1:{did}`) and its synced-store accessors — see module doc |
| `sovereign_session.rs` | passwordless per-DID sovereign login: device-key proof → validated Bearer session persisted to `{did}:oauth-tokens`; owns the shared sub/aud binding helpers — see module doc |
| `session_provider.rs` | the per-DID session seam every authenticated operation goes through: restore / coalesced single-flight refresh / host-change discard, distinct terminal errors, and the `ensure_identity_session` pre-flight — see module doc |
| `password_unlock.rs` | the password origin for the shared session record on non-sovereign hosts: capability-driven route choice (unreached ⇒ SOVEREIGN) + `createSession` → bind → persist — see module doc |
| `source_login.rs` | the one shared password `createSession` core (HTTPS + account-match + 2FA) behind the claim, migration, and password-unlock paths (ADR-0021) — see module doc |
| `oauth.rs` | `AppState` (all flow-state slots) + the retired OAuth PKCE machinery (`prepare/complete_oauth_flow`, no live caller); slot inventory and the create-flow-ends-at-home retirement rationale in the module doc |
| `oauth_client.rs` | `OAuthClient`, the authenticated XRPC client: DPoP and Bearer modes, lazy refresh, nonce retry, non-nonce 400s passed through intact — see module doc |
| `http.rs` | `CustosClient` for the one configured PDS (runtime URL, Keychain-persisted); OAuth `par`/`token_exchange` — see module doc |
| `pds_client.rs` | discovery/auth/XRPC against arbitrary PDSes + plc.directory, the wallet's OAuth identity constants (canonical client_id, reverse-FQDN redirect, V042 sync), and the status-classification seam (`NetworkError` is transport-only); full inventory and error reachability in the module doc |
| `pds_capabilities.rs` | per-host cache of `describeServer`'s `custos` extension; absence is not an error, gates ask about features never vendors — cache contract in the module doc |
| `claim.rs` | the 5-command PLC claim pipeline (password source login per ADR-0021; a claim changes nothing but inserting the device key) — see module doc |
| `migrate.rs` | self-signed migration identity leg (ADR-0002 path 1): build + device-key-sign + direct plc.directory submit; also the did:web document leg; `guard_migration_op`'s allowlist and the claim-guard inversion in the module doc |
| `migration_orchestrator.rs` | the outbound-migration state machine (prepare → … → finalize; also disaster recovery's transfer tail); cutover ordering, the capability-gated credential branch, blob-loss handling, and state-vs-session persistence in the module doc |
| `disaster_recovery.rs` | sovereign disaster recovery ("Rebuild from backup"): two guarded PLC ops around an offline-JWT `createAccount` + iCloud-CAR import; sequencing and the anti-lockout rule in the module doc |
| `endpoint_repair.rs` | sovereign `atproto_pds`-endpoint repair (device-key-signed, direct to plc.directory; new host probed first); the endpoint-string-only guard and its no-op reconcile in the module doc |
| `handle_change.rs` | sovereign change-handle: `updateHandle` first, device-key-signed alsoKnownAs op second, retry self-heals; guard and error classifiers in the module doc |
| `rotate_repo_key.rs` | sovereign repo signing-key rotation (ADR-0025): PDS stages, wallet signs, PDS submits + cuts over under the repo write lock — see module doc |
| `self_held_kit.rs` | escrow-less self-held Shamir kit for claimed identities: build/submit/confirm + the escrow-offer seam; share custody and the plc.directory-only posture in the module doc |
| `identity_removal.rs` | permanent removal: `deleteAccount` → (did:plc) tombstone → wipe-last, resumable via the pending-removals marker; password-vs-signed-proof resolution and the local-only forget hatch in the module doc |
| `recovery.rs` | the recovery override: fork-point counter-op signed by the device key, inside plc.directory's 72-hour window — see module doc |
| `plc_monitor.rs` | background + foreground PLC sweeps over did:plc identities only (omission is not a verdict) and the fold-based sweep history behind the Protection surface — set rule, degradation contract, and fold rules in the module doc |
| `agents.rs` | agent consent + audit: the 5 per-identity "My agents" + claim-ceremony commands over a self-healing per-DID session — see module doc |
| `oauth_consent.rs` | wallet-confirmed OAuth consent client (preview by code / by QR `request_id`, device-key-signed approve); envelope contents and Phase C match-code rules in the module doc |
| `app_passwords.rs` | app-password mint/list/revoke over a per-DID full-access session (the "sign the Bluesky app into a passwordless account" surface) — see module doc |
| `blob_backup.rs` | user-held media backup: CID-verified incremental iCloud mirror + per-blob-degrading restore; also feeds the migration blob drain (`mirror_fallback_blob`) and the background sweep — see module doc |
| `repo_backup.rs` | user-held posts backup, sibling of `blob_backup.rs`: client-validated full-CAR `getRepo` snapshot into the same iCloud container (no session); `mirror_repo_car` is the migration/disaster-recovery repo source — see module doc |
| `bg_backup.rs` | iOS `BGProcessingTask` keeping both iCloud mirrors topped up: alternating two-mirror sweep, per-DID opt-ins, app-global settings; scheduler-bridge invariants (plist sync, completion latch, wifiOnly path) in the module doc |
| `notifications.rs` | device half of the E2E-encrypted notification relay: device-global keypair/uuid, per-host pinned sender keys, register + re-pin, and the extension's `notification-failures` breadcrumb slot — design invariants in the module doc |
| `apns.rs` | iOS-only APNs bridge: add-only delegate-method installation for the token callbacks + the notification-tap deep link — see module doc |
| `notification_routes.rs` | the host-tested half of notification-tap routing: one newest-wins pending-route slot drained by `take_pending_notification_route`; pointer-not-claim discipline in the module doc |
| `diagnostics.rs` | redacted-by-construction network-error breadcrumbs, exported on demand from Settings; capture scope and redaction rules in the module doc |

**Guarantees (cross-cutting):**
- `crate-type = ["staticlib", "cdylib", "rlib"]` supports iOS, Android, and normal cargo
  builds; `src/main.rs` is the desktop entry point, `src/lib.rs::run()` the mobile one.
- `tauri.conf.json` is read at compile time by `generate_context!()` — it must exist before
  `src-tauri/` compiles.
- The OAuth callback is delivered by ASWebAuthenticationSession (the vendored
  `tauri-plugin-auth-session`), never a deep link — iOS Safari won't auto-launch an app from
  a server-side redirect to a custom scheme. The scheme `org.obsign.identitywallet` is
  registered in `src-tauri/Info.ios.plist`. Flow detail: `oauth.rs`'s module doc and
  `vendor/tauri-plugin-auth-session/VENDORED.md`.

**Expects:** `cargo-tauri` in PATH (Nix dev shell); Xcode + iOS Simulator for device work; a
PDS running at the configured URL for account creation to succeed at runtime.

## Dependencies

- Frontend → Rust via Tauri IPC (`@tauri-apps/api/core` `invoke()`).
- Rust → workspace deps: `crates/crypto` (P-256 software path + envelope builders), `p256`,
  `multibase`, `hickory-resolver` (DNS TXT handle resolution), `urlencoding`, `chrono`;
  reqwest is rustls-only (no OpenSSL — rustls handles iOS TLS natively).
- Rust → the configured PDS, arbitrary PDSes, and plc.directory over HTTPS at runtime (the
  endpoint inventory is each client module's doc: `http.rs`, `pds_client.rs`).
- Rust/frontend → `tauri-plugin-auth-session` (**vendored** in
  `vendor/tauri-plugin-auth-session/`; see VENDORED.md for provenance + audit).
- iOS-only target deps: `security-framework` (Keychain + Secure Enclave),
  `objc2-foundation` (iCloud ubiquity container), `objc2-background-tasks` + `block2`
  (BGTaskScheduler), `objc2-ui-kit`/`objc2-user-notifications` (APNs bridge),
  `system-configuration` (Wi-Fi-only check).
- `src-tauri/gen/` is NOT tracked — generated per developer by `cargo tauri ios init`.

## Prerequisites (macOS/iOS Development)

1. **macOS Ventura (13) or later**
2. **Xcode** (latest stable, from App Store). Open it once to accept the license — skipping
   this makes `cargo tauri ios dev` fail silently. Install the iOS Simulator platform
   (Settings → Platforms → iOS).
3. **Cocoapods** (`sudo gem install cocoapods`) — Tauri's iOS build links native frameworks
   with it.
4. **Apple Developer account** — optional for Simulator; required for physical-device
   (TestFlight/App Store) builds.

## First-Time Setup

Once per developer machine:

```bash
# 1. Enter the Nix dev shell from the WORKSPACE ROOT (CARGO_HOME resolves relative to
#    devenv root). First entry installs the Rust toolchain + iOS targets via rustup
#    (reads rust-toolchain.toml; ~2-4 GB download).
nix develop --impure --accept-flake-config

# 2. Install frontend dependencies
cd apps/identity-wallet && pnpm install

# 3. Generate the Xcode project (src-tauri/gen/apple/ — gitignored, machine-specific)
cargo tauri ios init

# 4. Finish + verify (swift-rs fork check + app icon + full ios-check)
cd .. && just ios-postinit
```

### After every `cargo tauri ios init`: run `just ios-postinit`

The init regenerates the gitignored Xcode project, rendering the committed XcodeGen template
`scripts/ios/project.yml` (via `bundle > iOS > template` in `tauri.conf.json` — the path is
cwd-relative, so run the init from `apps/identity-wallet/`). The template carries every
Xcode-project workaround declaratively; what each one fixes is the Troubleshooting section
below. `just ios-postinit` verifies the swift-rs fork wiring, regenerates the AppIcon
catalog, and runs `just ios-check`, which fails loudly if the template did not apply.

### Why rustup instead of Nix-managed Rust

Nix's `rust-default` ships no iOS cross-compilation stdlibs; rustup downloads
`aarch64-apple-ios-sim` and friends from the Rust release infrastructure. The dev shell uses
project-local `RUSTUP_HOME`/`CARGO_HOME` (inside `.devenv/state/`).

The Apple toolchain (clang/ar/SDKs/`DEVELOPER_DIR`) is resolved dynamically by
`scripts/ios-env.sh` (a thin wrapper over the shared `scripts/ios/ios-env.sh`), sourced by
devenv `enterShell` and by the Xcode Run Script phase so CLI and Xcode builds agree. Its
subtleties — stripping the Nix apple-sdk stub's `DEVELOPER_DIR`/`SDKROOT` (only when they
point into `/nix/store`), and gating the macOS-host `CC`/linker overrides behind
`EZPDS_IOS_BUILD=1` so a plain `cargo build --workspace` is untouched — are documented in
the script itself.

## Development Workflow

```bash
# From the workspace root, inside the dev shell:
just ios-dev                       # auto-select (a connected device wins over the Simulator)
just ios-dev "iPhone 17 Pro Max"   # force a specific simulator
just ios-build                     # build only (no Simulator launch)
```

Both recipes run `just ios-check` first (fails fast if the generated project is missing a
patch — run `just ios-postinit`), then re-source `ios-env.sh` with `EZPDS_IOS_BUILD=1` so a
long-lived shell's stale toolchain env can't reach the build through the shared `target/`.

**Do not click Run in Xcode directly** — `just ios-dev` starts the JSON-RPC server Xcode's
build phase connects to; bypassing it yields "Connection refused" (see Troubleshooting).

For a non-iOS build (CI or any machine without Xcode): `cargo build` from the workspace root.

## CI / TestFlight

The iOS app builds in GitHub Actions (`.github/workflows/ios-testflight.yml`, free
`macos-26` runner) on every push to `main`: regenerate the Xcode project, build a signed
App Store IPA, upload to TestFlight. Signing is **explicit** (Tauri's automatic signing
emits a placeholder App Store rejects — tauri#11092): `IOS_CERTIFICATE` /
`IOS_CERTIFICATE_PASSWORD` / `IOS_MOBILE_PROVISION`, with the App Store Connect API key
used only for the `altool` upload. The build/upload core is shared `just` recipes
(`ios-ipa` stamps a monotonic `bundleVersion`, `ios-upload`, `ios-release`) so CI and local
runs are identical; the workflow never runs on `pull_request` (keeps secrets off fork PRs).
Full setup and gotchas: **[docs/ios-cicd.md](../../docs/ios-cicd.md)**.

## Key Decisions

- **`adapter-static` + `ssr = false` + `pages: 'dist'`**: Tauri WebViews load files from
  disk; there is no web server.
- **`TAURI_DEV_HOST` for HMR**: the iOS simulator connects to Vite over LAN, not localhost.
- **Toolchain via `ios-env.sh`, no hardcoded Xcode paths** — see First-Time Setup above and
  the script's own comments.
- **Runtime-configurable PDS URL**: compile-time default is only the pre-filled value; the
  user configures on first launch and the URL persists in the Keychain (`http.rs`).
- **The create flow ends at `home`, with no OAuth round trip** — the retired machinery and
  the evidence for removing it: `oauth.rs`'s module doc.
- **Source logins are password-based, not OAuth (ADR-0021)** — the shared core and why no
  OAuth token can drive identity ops: `source_login.rs`'s module doc.
- **One situation question as entry point**, and **`server_gone` is routing, not a flow** —
  rationale on `AddIdentityScreen` / `ServerGoneScreen`.
- **Native SwiftUI migration is deferred, trigger-gated** — ADR-0013; port the shell, never
  the crypto.

## Invariants

- **Bundle identity is pinned.** `tauri.conf.json`'s `dev.malpercio.identitywallet` is
  enforced by `just bundle-identity-check` and cannot be renamed as a one-line diff: it used
  to double as the Keychain access group and the iCloud container id (ADR-0030), a rename is
  a NEW App Store record, and the gate's header carries the full rename checklist.
- **Keychain access groups**: declared in `src-tauri/Entitlements.ios.plist`, where the
  array **order is the mechanism** (stable group `org.obsign.shared` first; the legacy group
  stays declared indefinitely). The full design is `keychain.rs`'s module doc; asserted at
  compile time there (`entitlement_declares_stable_group_first`) and in CI by
  `just bundle-identity-check`.
- The iCloud container id `iCloud.dev.malpercio.identitywallet` is **frozen permanently**,
  bundle renames included — `just bundle-identity-check` asserts it against a literal.
- **Keychain accounts**: `keychain.rs`'s module doc is the canonical inventory (app-global
  accounts, the per-DID `"{did}:suffix"` pattern, the synced-store allowlist where Share 1
  is the sole member, protection classes). The service name `"ezpds-identity-wallet"`
  never changes — changing it orphans every stored credential.
- **Wire contract**: the single serde rule in the Rust Backend section above; per-enum
  variant lists live in the module docs, and their `$lib/ipc` TypeScript counterparts must
  match exactly.
- **OAuth client identity**: `pds_client::CANONICAL_CLIENT_ID` and `REDIRECT_URI` must stay
  in sync with the Custos client-metadata route and the V042-seeded `oauth_clients` row —
  see `pds_client.rs`'s module doc.
- Constants with product meaning: PLC monitoring interval 15 min
  (`plc_monitor::MONITOR_INTERVAL_SECS`), recovery window 72h (`deadline.ts`, matching
  plc.directory), both apps' `minimumSystemVersion` 17.0 (CryptoKit HPKE floor for the
  Notification Service Extension; set only in the two `tauri.conf.json` files).
- `src-tauri/gen/` is never committed; `pnpm-lock.yaml` is committed and kept in sync.
- `registerForNotifications` runs at every onboarding completion and once per app open per
  identity — a **security property**, not housekeeping (re-pin cadence bounds a compromised
  sender key's window; see `notifications.rs`).

## Key Files (non-source)

- `src-tauri/tauri.conf.json` — bundle id, devUrl, frontendDist, `bundle > iOS`
  (template path, frameworks list, minimumSystemVersion).
- `src-tauri/Entitlements.ios.plist` — the TRACKED code-signing entitlements: Keychain
  access groups (order-sensitive — see Invariants), iCloud Documents container, and
  `aps-environment` for push. Installed into the generated project by `ios-postinit`'s
  Patch H (tauri's build-time codesign reads the default generated path, so the tracked
  content must be copied there — the template's `entitlements > path` is ignored by the
  signer). The App ID + provisioning profile must carry the matching iCloud + push
  capabilities; `just ios-template-check` (source) and `just ios-check` (generated) guard
  the container-id sync with `Info.ios.plist`'s `NSUbiquitousContainers`.
- `scripts/ios/project.yml` (repo root) — the SHARED forked XcodeGen template for both iOS
  apps, rendered by every `cargo tauri ios init`; carries every workaround declaratively
  (each one's story is in Troubleshooting). `just ios-template-check` keeps the fork in
  lockstep with the workflows' tauri-cli pin.
- `apps/identity-wallet/scripts/ios-{env,postinit,check}.sh` — thin wrappers over the ONE
  shared implementation in `scripts/ios/` (repo root). Edit the shared scripts, never a
  wrapper copy.
- `apps/identity-wallet/app-icon.svg` + `AppIcon.icon/` — the icon's vector source and the
  layered Icon Composer document for the iOS 26 Liquid Glass icon (no baked shadows).
  To change the icon: edit the SVG, re-render `app-icon.png` at 1024×1024, commit both,
  re-run `just ios-postinit`. The `.icon` package is compiled/validated by actool in
  `just ios-pr-check`.
- `vendor/tauri-plugin-auth-session/` — vendored ASWebAuthenticationSession plugin (path
  dep, excluded from the workspace); provenance + audit in VENDORED.md.
- `src-tauri/.cargo/config.toml` — only `RUST_TEST_THREADS=1`; all toolchain overrides live
  in `ios-env.sh`.

## Troubleshooting

### `cargo tauri ios dev` fails with "Connection refused"

You clicked Run in Xcode. The "Build Rust Code" phase connects back to the
`cargo tauri ios dev` process via JSON-RPC; there is no server unless that process started
the build. Always launch from the terminal.

### `error: can't find crate for 'core'` — `aarch64-apple-ios-sim` missing

Resolved by the rustup migration (see First-Time Setup). If it appears on a fresh clone,
you entered the dev shell from a subdirectory — re-enter from the workspace root so
`CARGO_HOME` resolves.

### `simctl` not found / `xcrun simctl list` fails

The Nix Darwin stdenv points `DEVELOPER_DIR`/`SDKROOT` at a tool-less apple-sdk stub, and
`xcode-select -p`/`xcrun` honor those env vars above the system Xcode selection.
`ios-env.sh` (sourced by `enterShell`) strips them when they point into `/nix/store`. If it
persists: `echo $DEVELOPER_DIR` — a Nix store path means re-enter the shell from the root.

### `sandbox-exec: sandbox_apply: Operation not permitted` (Tauri ios-api build)

macOS 26 returns `EPERM` for SPM's manifest-compile sandbox. Fixed by the local `swift-rs`
patch (`apps/identity-wallet/swift-rs-patch/`, wired via `[patch.crates-io]`) adding
`--disable-sandbox`; see `docs/ios-upstream-bugs.md`. Remove when upstream ships a fix.

### `Failed to update the excludes stack …` (Xcode user script sandbox)

Xcode 14+'s `ENABLE_USER_SCRIPT_SANDBOXING=YES` blocks Cargo's `readdir()` on macOS 26. The
template sets it to `NO`; `just ios-check` verifies.

### `Undefined symbols ... _SC*` / `_ASWebAuthenticationSession*` at `Ld`

An Apple framework a Rust crate needs isn't linked in the Xcode project. Host builds link
fine (rustc honors the crate's `#[link]`); on iOS, Xcode does the final link of the
staticlib and never sees that directive. Fix by adding the framework to
`bundle > iOS > frameworks` in `tauri.conf.json` (the template renders `OTHER_LDFLAGS` and
xcodegen link deps from it) and re-running init + postinit — never hand-edit
`OTHER_LDFLAGS` (a second assignment shadows the first; `just ios-check` detects it).

### `libapp.a ... is not permitted` / `Invalid bundle structure` on TestFlight upload

cargo-mobile2 lists `Externals` with no `buildPhase`, so XcodeGen infers `resources` and
copies the raw staticlib into the bundle, which App Store validation forbids (tauri#13578).
The template sets `Externals → buildPhase: none`; the `framework: libapp.a` link dependency
is kept. `just ios-check` verifies both layers.

### `base64: invalid option -- 'o'` during signing

GNU coreutils `base64` shadows BSD `base64` in the Nix shell, and Tauri's cert decode uses
BSD-only flags. `ios-env.sh` (under `EZPDS_IOS_BUILD=1`) shims `/usr/bin/base64` ahead of
the Nix one.
