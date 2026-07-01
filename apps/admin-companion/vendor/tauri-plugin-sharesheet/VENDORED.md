# Vendored: tauri-plugin-sharesheet

Source: https://github.com/buildyourwebapp/tauri-plugin-sharesheet
crates.io `tauri-plugin-sharesheet` v0.0.1 (published 2024-08-29 — the only release)
License: MIT (see LICENSE)

Vendored (not a crates.io dependency) because the sole upstream release injects an iOS
entitlement the app does not use, and there is no fixed version to upgrade to. Only the Rust
crate — which carries the offending `build.rs` — is vendored; the npm guest API
(`@buildyourwebapp/tauri-plugin-sharesheet`) is kept from the registry, since the app invokes
`plugin:sharesheet|share_text` from `src/lib/share.ts`.

## Local modifications to the upstream source

- **`build.rs`**: removed the `#[cfg(target_os = "macos")]` block that inserted
  `com.apple.developer.group-session` (Group Activities / SharePlay) into the consuming app's
  iOS entitlements via `tauri_plugin::mobile::update_entitlements`. The Share Pane
  (`UIActivityViewController`) does not use SharePlay, so declaring that entitlement forced the
  App Store provisioning profile to carry an unused capability and failed `exportArchive` with
  *"requires a provisioning profile with the Group Activities feature."* Removing it lets the
  profile stay minimal (the app declares no special capabilities). The `share_text` command is
  unaffected — the entitlement was over-declared by the plugin author.
- **`Cargo.toml`**: added `publish = false` (private fork — must never be released to crates.io
  under the upstream's name/metadata).
- **Pruned** the non-build files (`guest-js/`, `package.json`, `pnpm-lock.yaml`, the JS build
  tooling, `.github/`, and cargo registry markers). Only the Rust crate plus its
  `ios/` / `android/` / `permissions/` / `api-iife.js` build inputs are kept.
- **Reformatted `src/`** with the repo's rustfmt (4-space). `cargo fmt --all --check` formats
  vendored *path* dependencies too (not just workspace members), so the upstream's 2-space
  source failed the format gate. Whitespace only — no semantic change.

## Why the entitlement removal is safe

`update_entitlements` runs in the plugin's `build.rs` on every iOS build (the `TAURI_IOS_*`
env vars are set by `cargo tauri`), so it re-adds the entitlement into the generated
`gen/apple/<app>_iOS/<app>_iOS.entitlements` even after a post-init strip. Removing it at the
source is the only reliable fix — a `just admin-postinit` step would be clobbered by the build
itself.

To update: no upstream update exists as of this writing (v0.0.1 is the only release). If one
appears, re-copy from it, re-apply the `build.rs` entitlement removal + `publish = false`, and
re-audit `build.rs` + `ios/Sources/SharesheetPlugin.swift`.
