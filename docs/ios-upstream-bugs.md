# iOS build: upstream bugs we work around locally

These are macOS/Xcode bugs (not Nix-specific) that the identity-wallet iOS build
works around locally. They are **not yet filed upstream** — file/PR them when
convenient, then delete the corresponding workaround and the references below.

Last updated: 2026-07-08. Environment where observed: macOS 26 (Tahoe), Xcode
(latest stable at time of writing), Tauri v2, swift-rs 1.0.7.

Since 2026-07: Bugs 2 and 3 are worked around **declaratively** in the committed
XcodeGen template `scripts/ios/project.yml` (rendered into `gen/apple/project.yml`
on every `cargo tauri ios init` via `bundle > iOS > template` in each app's
tauri.conf.json) rather than by regex-patching the generated pbxproj. Known
related upstream issues: the env/PATH gap the template's Build Rust Code preamble
covers is tauri#10672 / tauri#11899 (open); the libapp.a bundle-structure fix
carried in the same template is tauri#13578 (open).

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
invocation (`swift-rs-patch/src-rs/build.rs:265`), wired via `[patch.crates-io]` in
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

**Workaround (in this repo):** the committed XcodeGen template
`scripts/ios/project.yml` sets `ENABLE_USER_SCRIPT_SANDBOXING: NO` in the target's
build settings; `cargo tauri ios init` renders it into `gen/apple/project.yml` and
xcodegen writes the setting into the generated pbxproj. `just ios-check` verifies
the setting landed.

**Reproduction:** remove the `ENABLE_USER_SCRIPT_SANDBOXING: NO` line from the
template, `cargo tauri ios init`, build → fails with the symptom above.

**Upstream:** Tauri / cargo-tauri (https://github.com/tauri-apps/tauri). File:
generated iOS projects should set `ENABLE_USER_SCRIPT_SANDBOXING = NO` (or declare
the Cargo dirs as script inputs). **Remove the template's
`ENABLE_USER_SCRIPT_SANDBOXING: NO` setting when fixed upstream.**

---

## Bug 3 — Xcode: spurious "Entitlements file was modified during the build" on incremental builds

**Symptom:**
```
error: Entitlements file "identity-wallet_iOS.entitlements" was modified during the
build, which is not supported. You can disable this error by setting
'CODE_SIGN_ALLOW_ENTITLEMENTS_MODIFICATION' to 'YES' ...
** BUILD FAILED **
```

**Cause:** `cargo tauri ios build` re-runs its project sync (`synchronize_project_config`)
on every invocation, restamping `project.pbxproj`. Xcode's incremental packaging
(`ProcessProductPackaging`) then racily flags the entitlements file as "modified during
the build" — even though it is an empty `<dict/>` that is **provably never modified**
(stamp it with an old mtime and it stays byte-identical through a failing build). It is
intermittent (~1 in 3 builds fail), which is the signature of a race, not a real change.

**Workaround (in this repo):** the committed XcodeGen template
`scripts/ios/project.yml` sets `CODE_SIGN_ALLOW_ENTITLEMENTS_MODIFICATION: YES` in
the target's build settings (the switch Xcode's own error names). Because the
entitlements is empty, permitting the modification cannot produce incorrect
entitlements — there is nothing to get wrong. The setting **survives** the
per-build sync, which preserves existing buildSettings.

**Reproduction:** Remove the setting from the template, re-init, then run
`just ios-build` repeatedly → intermittently fails with the symptom above.

**Upstream:** Tauri / cargo-mobile2 (the per-build pbxproj restamp via
`synchronize_project_config`) and/or Xcode (the spurious detection). **Remove the
template's `CODE_SIGN_ALLOW_ENTITLEMENTS_MODIFICATION` setting if Tauri stops
restamping the project on every build, or stops regenerating the entitlements.**
