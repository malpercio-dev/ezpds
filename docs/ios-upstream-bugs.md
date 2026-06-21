# iOS build: upstream bugs we work around locally

These are macOS/Xcode bugs (not Nix-specific) that the identity-wallet iOS build
works around locally. They are **not yet filed upstream** — file/PR them when
convenient, then delete the corresponding workaround and the references below.

Last updated: 2026-06-20. Environment where observed: macOS 26 (Tahoe), Xcode
(latest stable at time of writing), Tauri v2, swift-rs 1.0.7.

---

## Bug 1 — swift-rs: `sandbox_apply()` EPERM during SwiftPM manifest compilation (macOS 26)

**Symptom:**
```
sandbox-exec: sandbox_apply: Operation not permitted
... Failed to compile swift package Tauri
```

**Cause:** `swift-rs` 1.0.7's `SwiftLinker::link` runs `swift build` without
`--disable-sandbox`. On macOS 26, SwiftPM's manifest-compilation sandbox
(`sandbox_apply`) returns `EPERM` in this context, failing Tauri's `ios-api` build
step.

**Workaround (in this repo):** A vendored fork at
`apps/identity-wallet/swift-rs-patch/` adds `--disable-sandbox` to the `swift build`
invocation (`swift-rs-patch/src-rs/build.rs:264`), wired via `[patch.crates-io]` in
the workspace `Cargo.toml`.

**Reproduction:** Remove the `[patch.crates-io] swift-rs` line from `Cargo.toml`,
`cargo tauri ios build --debug` on macOS 26 → fails with the symptom above.

**Upstream:** swift-rs (https://github.com/Brendonovich/swift-rs). File: request
`--disable-sandbox` (configurable, or default on macOS 26). **Remove the fork and
the `[patch.crates-io]` entry when fixed upstream.**

---

## Bug 2 — Tauri iOS: generated project sets `ENABLE_USER_SCRIPT_SANDBOXING = YES`, blocking Cargo on macOS 26

**Symptom:**
```
error: failed to determine package fingerprint for build script for identity-wallet v0.1.0
Caused by: Failed to update the excludes stack to see if a path is excluded
```

**Cause:** `cargo tauri ios init` generates an Xcode project with
`ENABLE_USER_SCRIPT_SANDBOXING = YES` (Xcode 14+ default). On macOS 26 the Run
Script sandbox blocks Cargo's `readdir()` during package fingerprinting.

**Workaround (in this repo):** `apps/identity-wallet/scripts/ios-postinit.sh` sets
`ENABLE_USER_SCRIPT_SANDBOXING = NO` in the generated `project.pbxproj` (re-applied
after every `cargo tauri ios init`).

**Reproduction:** `cargo tauri ios init` then build WITHOUT running
`just ios-postinit` → fails with the symptom above.

**Upstream:** Tauri / cargo-tauri (https://github.com/tauri-apps/tauri). File:
generated iOS projects should set `ENABLE_USER_SCRIPT_SANDBOXING = NO` (or declare
the Cargo dirs as script inputs). **Remove the postinit sandbox patch when fixed
upstream.**
