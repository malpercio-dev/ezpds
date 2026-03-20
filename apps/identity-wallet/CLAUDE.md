# Identity Wallet Mobile App

Last verified: 2026-03-20

## Purpose

Tauri v2 iOS application — SvelteKit 2 + Svelte 5 frontend running in a native WKWebView, communicating with a Rust backend exclusively through Tauri's IPC bridge. First frontend code in the repository.

## Contracts

### Frontend (SvelteKit 2 + Svelte 5)

**Exposes:**
- `src/lib/ipc.ts` — typed wrappers for all Tauri IPC commands; import these instead of calling `invoke()` directly. Exports: `createAccount()`, `getOrCreateDeviceKey()`, `signWithDeviceKey()`, and their associated types (`DevicePublicKey`, `DeviceKeyError`, `CreateAccountResult`, `CreateAccountError`)
- `src/lib/components/onboarding/` — five onboarding screen components (WelcomeScreen, ClaimCodeScreen, EmailScreen, HandleScreen, LoadingScreen)
- `src/routes/+page.svelte` — root page: five-screen onboarding state machine (welcome -> claim_code -> email -> handle -> loading -> did_ceremony)

**Guarantees:**
- SSR is disabled globally (`ssr = false` in `src/routes/+layout.ts`); the frontend is a fully static SPA loaded from disk by WKWebView
- Build output lands in `dist/` (configured via `pages: 'dist'` in `svelte.config.js`)
- Frontend calls Tauri commands only through `src/lib/ipc.ts` — no raw `invoke()` calls in page components
- Relay error codes from `create_account` are mapped back to the originating screen (e.g. EXPIRED_CODE -> claim_code step, EMAIL_TAKEN -> email step)

**Expects:**
- `pnpm install` has been run in `apps/identity-wallet/`
- Node.js 22.x is in PATH (provided by the Nix dev shell)

### Rust Backend (src-tauri/)

**Exposes:**
- `src/lib.rs::create_account(claim_code, email, handle) -> Result<CreateAccountResult, CreateAccountError>` — Tauri IPC command: gets or creates device key via `device_key::get_or_create()`, POSTs to relay `/v1/accounts/mobile`, stores tokens in Keychain on success
- `src/lib.rs::get_or_create_device_key() -> Result<DevicePublicKey, DeviceKeyError>` — Tauri IPC command: delegates to `device_key::get_or_create()`
- `src/lib.rs::sign_with_device_key(data: Vec<u8>) -> Result<Vec<u8>, DeviceKeyError>` — Tauri IPC command: delegates to `device_key::sign()`
- `src/device_key.rs` — P-256 device key management with `#[cfg]`-based dispatch: macOS/simulator uses software keys via `crypto` crate + Keychain storage; real iOS device uses Secure Enclave via `security-framework`. Public API: `get_or_create() -> Result<DevicePublicKey, DeviceKeyError>` (idempotent), `sign(data) -> Result<Vec<u8>, DeviceKeyError>`
- `src/keychain.rs` — iOS Keychain abstraction (`store_item`, `get_item`, `delete_item`) under service `"ezpds-identity-wallet"`
- `src/http.rs` — `RelayClient` with compile-time base URL (localhost:8080 debug, relay.ezpds.com release)

**Guarantees:**
- `crate-type = ["staticlib", "cdylib", "rlib"]` supports iOS (staticlib), Android (cdylib), and normal cargo builds (rlib)
- `src/main.rs` is the desktop entry point; `src/lib.rs::run()` is the iOS/Android entry point (via `#[cfg_attr(mobile, tauri::mobile_entry_point)]`)
- `tauri.conf.json` configures the bundle identifier, dev URL (`http://localhost:5173`), and frontend dist path (`../dist`)
- `create_account` maps relay HTTP error codes to typed `CreateAccountError` variants (EXPIRED_CODE, REDEEMED_CODE, EMAIL_TAKEN, HANDLE_TAKEN, NETWORK_ERROR, UNKNOWN) serialized as `{ code: "SCREAMING_SNAKE" }` for the frontend
- `device_key::get_or_create()` is idempotent -- returns the same key on every call for a given device
- `device_key::sign()` returns raw 64-byte r||s ECDSA signatures; deterministic (RFC 6979) on simulator, low-S normalized on real device
- `DeviceKeyError` variants serialize as `{ code: "SCREAMING_SNAKE_CASE" }` matching the `CreateAccountError` pattern
- Device key dispatch: `#[cfg(any(target_os = "macos", all(target_os = "ios", target_env = "sim")))]` for software path, `#[cfg(all(target_os = "ios", not(target_env = "sim")))]` for Secure Enclave path

**Expects:**
- `tauri.conf.json` exists in `src-tauri/` before `cargo build` runs — the config is read at compile time by `generate_context!()`
- `cargo-tauri` is in PATH (provided by the Nix dev shell)
- Xcode and iOS Simulator are installed on the developer's macOS machine
- Relay must be running at the compile-time URL for `create_account` to succeed at runtime

## Dependencies

- Frontend -> Rust backend (via Tauri IPC -- `@tauri-apps/api/core` `invoke()`)
- Rust backend -> Cargo workspace (inherits `version`, `edition`, `publish` from root `Cargo.toml`)
- Rust backend -> `crates/crypto` (workspace dep: P-256 key generation in simulator/macOS software path)
- Rust backend -> `p256` (workspace dep: key reconstruction, signature types in both paths)
- Rust backend -> `multibase` (workspace dep: base58btc encoding for multibase/did:key output)
- Rust backend -> relay `/v1/accounts/mobile` endpoint (via `reqwest` HTTP at runtime)
- Rust backend -> iOS Keychain (via `security-framework` crate with `OSX_10_12` feature for SE access control APIs)
- Rust backend -> Secure Enclave hardware (real iOS device only; via `security-framework` `SecKey`/`GenerateKeyOptions`/`Token::SecureEnclave`)
- `src-tauri/gen/` -> NOT tracked in git; generated per-developer by `cargo tauri ios init` (gitignored)

## Prerequisites (macOS/iOS Development)

1. **macOS Ventura (13) or later**

2. **Xcode** (latest stable, from App Store)
   - After installing, open Xcode.app once to accept the license agreement — failing to do this causes `cargo tauri ios dev` to fail silently
   - Install the iOS Simulator platform: Xcode → Settings → Platforms → iOS

3. **Cocoapods** — Tauri's iOS build uses it to link native Apple frameworks:
   ```bash
   sudo gem install cocoapods
   ```

4. **Apple Developer account** — optional for Simulator; required for physical device (TestFlight/App Store) builds

## First-Time Setup

After cloning the repo, perform these steps once per developer machine:

```bash
# 1. Enter the Nix dev shell (provides cargo-tauri, node 22, pnpm, rustup)
#    On first entry, enterShell installs the Rust toolchain + iOS targets via rustup.
#    This reads rust-toolchain.toml and may download ~2-4 GB — takes a few minutes.
nix develop --impure --accept-flake-config

# 2. Install frontend dependencies
cd apps/identity-wallet
pnpm install

# 3. Generate the Xcode project (output is in src-tauri/gen/apple/ — gitignored)
cargo tauri ios init
```

Note: `src-tauri/gen/` contains a machine-specific Xcode project. It is gitignored and must be re-generated on each developer machine. Do not commit it.

### Xcode build phase PATH (one-time manual step after `cargo tauri ios init`)

Xcode's Run Script build phases do not inherit the Nix dev shell PATH. After regenerating `src-tauri/gen/`, the generated `project.pbxproj` script must be patched to expose both the devenv tools and the rustup-managed cargo:

Open `src-tauri/gen/apple/identity-wallet.xcodeproj/project.pbxproj` and find the `shellScript` line in the PBXShellScriptBuildPhase section. Prepend:

```
export PATH="<project-root>/.devenv/state/cargo/bin:<project-root>/.devenv/profile/bin:$PATH"
```

where `<project-root>` is the absolute path to the repo root (e.g. `/Users/you/workspace/malpercio-dev/ezpds`).

This step is required once per `cargo tauri ios init` run.

### Why rustup instead of Nix-managed Rust

`languages.rust` in devenv uses Nix's `rust-default` package, which only ships stdlibs for standard host targets. iOS Simulator requires `aarch64-apple-ios-sim` stdlib. Nix doesn't package iOS cross-compilation stdlibs; `rustup` downloads them from the Rust release infrastructure. The dev shell is configured with project-local `RUSTUP_HOME` and `CARGO_HOME` (inside `.devenv/state/`) so the toolchain is isolated per project.

## Development Workflow

```bash
# Enter the dev shell if not already active (MUST be run from the workspace root,
# not from apps/identity-wallet/ — CARGO_HOME resolves relative to devenv root)
nix develop --impure --accept-flake-config

# Launch the app in the iOS Simulator
# This starts pnpm dev + compiles the Rust crate for aarch64-apple-ios-sim + opens the Simulator
cd apps/identity-wallet
cargo tauri ios dev
```

**Do not click Run in Xcode directly.** `cargo tauri ios dev` starts a JSON-RPC server that
Xcode's build phase connects to; bypassing it causes "Connection refused" in the build log.

For a non-iOS build (CI or any machine without Xcode):

```bash
# From workspace root — builds all workspace crates including src-tauri for the host platform
cargo build
```

## Key Decisions

- **`adapter-static` + `ssr = false`**: Tauri WebViews load files from disk — there is no web server. SSR is meaningless and globally disabled.
- **`pages: 'dist'` in svelte.config.js**: Matches `tauri.conf.json`'s `frontendDist: "../dist"`.
- **`TAURI_DEV_HOST` for HMR**: Tauri v2 automatically sets this env var to the machine's LAN IP when running `cargo tauri ios dev`. The iOS simulator connects to the Vite dev server over LAN, not localhost.
- **`generate_context!()` is compile-time**: `tauri.conf.json` must exist when `src-tauri/` is compiled — the macro embeds the config at compile time and will fail to compile if the file is missing.
- **`src-tauri/gen/` is gitignored**: The Xcode project generated by `cargo tauri ios init` is machine-specific. Committing it causes merge conflicts and bloats the repo.
- **`tauri` and `tauri-build` declared locally**: These crates are not in `[workspace.dependencies]` because no other workspace crate uses them. `serde` and `serde_json` use `{ workspace = true }` per the standard workspace pattern.
- **`src-tauri/.cargo/config.toml` committed**: Overrides `CC`, `AR`, and `linker` for iOS, iOS Simulator, and macOS-host targets to use Xcode's unwrapped clang instead of the Nix cc-wrapper. The macOS-host `CC`/`AR` overrides (`CC_aarch64_apple_darwin`, `AR_aarch64_apple_darwin`) were added for `security-framework`'s C build scripts which fail under Nix's cc-wrapper. See the Troubleshooting section for the full explanation.
- **Compile-time relay URL**: `http.rs` uses `#[cfg(debug_assertions)]` to switch between localhost:8080 (debug) and relay.ezpds.com (release). No runtime configuration needed for the base URL.
- **Device key module (`device_key.rs`) with `#[cfg]` dispatch**: Two compile-time paths share the same public API (`get_or_create`, `sign`). macOS and iOS Simulator use software P-256 via `crypto` crate with private key bytes in Keychain. Real iOS device uses Secure Enclave -- private key never leaves the SE; only the compressed public key and application_label (SE-assigned SHA1) are stored in regular Keychain for lookup.
- **Idempotent key lifecycle**: `get_or_create()` generates on first call, returns the same key on subsequent calls. `create_account` delegates to `device_key::get_or_create()` so the same device key is sent to the relay on every attempt (retries are safe).
- **P-256 multicodec prefix duplicated**: `device_key.rs` duplicates the `[0x80, 0x24]` P-256 multicodec varint prefix from `crates/crypto/src/keys.rs` because the constant is `pub(crate)` there. This is intentional -- the identity-wallet crate should not depend on internal crypto crate layout.
- **Low-S normalization on SE path**: Apple's Secure Enclave may produce high-S ECDSA signatures. The SE `sign()` path applies `normalize_s()` to ensure ATProto-compatible low-S form. The simulator path uses RFC 6979 deterministic nonces which already produce low-S.
- **reqwest with rustls-tls**: Uses `default-features = false` + `rustls-tls` to avoid linking OpenSSL. On iOS, rustls handles TLS natively without additional system deps.

## Invariants

- `src/lib/ipc.ts` is the only file that calls `invoke()` directly; page components import from `ipc.ts`
- `tauri.conf.json` bundle identifier `dev.malpercio.identitywallet` must match the iOS provisioning profile for physical device builds
- `src-tauri/gen/` is never committed -- regenerate with `cargo tauri ios init`
- `pnpm-lock.yaml` is committed and kept in sync with `package.json`
- Keychain service name is always `"ezpds-identity-wallet"` (constant `keychain::SERVICE`); changing it orphans previously stored credentials
- `CreateAccountError` variant names serialize as SCREAMING_SNAKE_CASE to the frontend -- the TypeScript `CreateAccountError.code` union must match exactly
- `DeviceKeyError` variant names serialize as SCREAMING_SNAKE_CASE to the frontend -- the TypeScript `DeviceKeyError.code` union must match exactly
- Keychain account `"device-rotation-key-priv"` stores the software P-256 private key (simulator/macOS path only); changing it orphans existing keys
- Keychain accounts `"device-rotation-key-pub"` and `"device-rotation-key-app-label"` store SE metadata (real iOS device path only); changing them orphans the SE key lookup
- `DevicePublicKey` serializes with `#[serde(rename_all = "camelCase")]` -- TypeScript receives `{ multibase, keyId }` (not `key_id`)

## Key Files

- `src-tauri/tauri.conf.json` -- Tauri config: bundle ID, devUrl, frontendDist, window settings
- `src-tauri/src/lib.rs` -- Tauri IPC commands (`create_account`, `get_or_create_device_key`, `sign_with_device_key`) and `run()` (mobile entry point)
- `src-tauri/src/device_key.rs` -- P-256 device key module: `#[cfg]`-dispatched `get_or_create()` and `sign()` (simulator software path vs. Secure Enclave)
- `src-tauri/src/main.rs` -- Desktop entry point (calls `lib::run()`)
- `src-tauri/src/keychain.rs` -- iOS Keychain abstraction (store_item, get_item, delete_item)
- `src-tauri/src/http.rs` -- RelayClient with compile-time base URL
- `src-tauri/.cargo/config.toml` -- Cargo toolchain overrides for iOS cross-compilation (CC, AR, linker per target)
- `src/lib/ipc.ts` -- Typed TypeScript wrappers for all Tauri IPC commands (createAccount, getOrCreateDeviceKey, signWithDeviceKey)
- `src/lib/components/onboarding/` -- Five onboarding screen components
- `src/routes/+page.svelte` -- Onboarding state machine (welcome -> claim_code -> email -> handle -> loading -> did_ceremony)
- `src/routes/+layout.ts` -- `ssr = false; prerender = false` (global SPA config)
- `svelte.config.js` -- adapter-static with `pages: 'dist'` (SPA mode, matches tauri.conf.json)
- `vite.config.ts` -- Tauri-compatible Vite server (clearScreen, HMR via TAURI_DEV_HOST, envPrefix)

## Troubleshooting

### `cargo tauri ios dev` fails with "Connection refused"

You launched the Xcode build manually (clicking Run in Xcode) instead of through `cargo tauri ios dev`. Xcode's "Build Rust Code" phase calls `cargo tauri ios xcode-script`, which connects back to the `cargo tauri ios dev` process via JSON-RPC. There is no server to connect to if the build was not initiated by `cargo tauri ios dev`.

**Fix:** Always use `cargo tauri ios dev` from the terminal. Do not click Run in Xcode.

---

### `error: can't find crate for 'core'` — `aarch64-apple-ios-sim` target not installed

The Nix `rust-default` package (used by `languages.rust` in devenv) does not ship iOS cross-compilation stdlibs. This was the historical state of the project before the rustup migration.

**Fix:** Already resolved. `devenv.nix` uses `pkgs.rustup` with project-local `RUSTUP_HOME`/`CARGO_HOME`. On first `nix develop`, `enterShell` runs `rustup toolchain install` which reads `rust-toolchain.toml` and installs `aarch64-apple-ios-sim` stdlib automatically.

If you see this after a fresh clone: make sure you entered the dev shell from the **workspace root** (not from `apps/identity-wallet/`) so that `CARGO_HOME` resolves correctly.

---

### `error: tool 'simctl' not found` or `xcrun simctl list` fails

The Nix devenv's Darwin setup hooks override `DEVELOPER_DIR` to a Nix apple-sdk stub that has no runtime tools. The `xcbuild` xcrun shim in PATH delegates to `$DEVELOPER_DIR/usr/bin/xcrun` — if `DEVELOPER_DIR` points at a Nix stub, it fails.

**Fix:** Already resolved. `devenv.nix`'s `enterShell` re-exports `DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer` after all Nix hooks run.

If you still see this: verify with `echo $DEVELOPER_DIR` inside the dev shell. If it shows a Nix store path, exit and re-enter the shell from the workspace root.

---

### `clang: error: invalid argument '-mmacos-version-min=14.0' not allowed with '-mios-simulator-version-min=14.0'`

The Nix cc-wrapper (in `.devenv/profile/bin/clang`) injects `-mmacos-version-min` for the host platform. When a build script (e.g. `objc2-exception-helper`) compiles Objective-C for the iOS simulator target, clang rejects both version flags simultaneously.

**Fix:** Already resolved. `src-tauri/.cargo/config.toml` sets `CC_aarch64_apple_ios_sim` and `CC_aarch64_apple_ios` to Xcode's unwrapped clang, which handles iOS targets correctly.

---

### `ld: library not found for -liconv` (host proc-macro build)

Rust proc-macros (e.g. `phf_macros`) are compiled for the host (`aarch64-apple-darwin`) even during an iOS cross-compilation build. The Nix cc-wrapper uses a partial Nix apple-sdk as sysroot, which omits some `/usr/lib` stubs including `libiconv.tbd`. The linker passes `-liconv` but can't find it.

**Fix:** Already resolved. `src-tauri/.cargo/config.toml` sets `[target.aarch64-apple-darwin].linker` to Xcode's clang and adds `rustflags = ["-L", ".../MacOSX.sdk/usr/lib"]` so the linker finds `/usr/lib` stubs (including `libiconv.tbd`) from the real Xcode SDK sysroot.

---

### `ld: framework not found UIKit` (iOS target final link)

The final link of `identity-wallet.dylib` for `aarch64-apple-ios-sim` uses `cc` (the Nix cc-wrapper) as the linker. The cc-wrapper injects its macOS sysroot even when rustc passes `-target arm64-apple-ios-simulator`, so the linker searches the macOS SDK and can't find iOS-only frameworks like UIKit.

**Fix:** Already resolved. `src-tauri/.cargo/config.toml` sets `[target.aarch64-apple-ios-sim].linker` to Xcode's clang, which handles the iOS sysroot and frameworks correctly.

---

### Xcode build phase: `cargo: command not found`

After running `cargo tauri ios init`, the generated `project.pbxproj` build script has the system PATH which doesn't include the Nix dev shell or rustup-managed cargo.

**Fix:** See "Xcode build phase PATH" in the First-Time Setup section above. Patch `project.pbxproj` to prepend `.devenv/state/cargo/bin` and `.devenv/profile/bin`.
