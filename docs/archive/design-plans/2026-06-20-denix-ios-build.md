# De-Nix the iOS Build Design

## Summary

The iOS build for `apps/identity-wallet` currently works but is fragile: the Nix cc-wrapper (which provides node, pnpm, cargo-tauri, and rustup) and Apple's Xcode toolchain must coexist in the same Cargo build, and they have conflicting ideas about the compiler, linker, and SDK. The existing workaround is a hand-maintained `.cargo/config.toml` file full of absolute paths like `/Applications/Xcode.app/...` that break whenever Xcode is updated, moved, or swapped via `xcode-select`. This plan removes every hardcoded path by introducing a single committed shell script (`ios-env.sh`) that derives the compiler, linker, host SDK path, and `DEVELOPER_DIR` at runtime from `xcrun` and `xcode-select` — so the build adapts to whatever Xcode the system is currently pointing at, rather than hardcoding a snapshot. With the overrides computed dynamically, `.cargo/config.toml` can be deleted entirely.

The "hybrid" part of the approach means Nix is kept as the sole provider of developer tools (node, pnpm, cargo-tauri, rustup) — only the Apple-toolchain coupling is de-hardcoded. Two consumers will source the same `ios-env.sh`: the devenv `enterShell` (covering CLI builds via `cargo tauri ios dev`/`build`) and the Xcode Run Script "Build Rust Code" phase (covering Xcode-driven builds). Three surviving workarounds that are macOS/Xcode problems rather than Nix problems — the `swift-rs` `--disable-sandbox` patch, the `project.pbxproj` PATH prepend, and `ENABLE_USER_SCRIPT_SANDBOXING = NO` — are automated into an idempotent `just ios-postinit` recipe and guarded by a `just ios-check` drift detector, rather than left as manual prose instructions.

## Definition of Done

- The iOS app (`apps/identity-wallet`) builds and runs in the iOS Simulator with **no hardcoded toolchain paths** anywhere in the repo. `apps/identity-wallet/src-tauri/.cargo/config.toml` is deleted; the cc-wrapper conflicts are resolved by a single committed env script that derives every path from `xcrun`/`xcode-select`, and none of the failures recur (`-mmacos-version-min` conflict, `-liconv` not found, `framework not found UIKit`).
- Nix/devenv remains the single tool provider — node, pnpm, cargo-tauri, and rustup all stay Nix-provisioned, and the build still runs from the devenv shell. Inside that shell, `just build` (`cargo build --workspace`), `just test`, `just clippy`, and `nix build .#relay --accept-flake-config` all still pass — in particular the host `security-framework` C build still links.
- The CLI build (`cargo tauri ios dev`/`build`) and the Xcode-driven build (Run Script "Build Rust Code" phase) resolve the toolchain from the **same** committed env script — one source of truth, no divergence.
- The Tauri/macOS workarounds that survive de-Nixing — the `swift-rs` `--disable-sandbox` patch, the `project.pbxproj` PATH prepend, and `ENABLE_USER_SCRIPT_SANDBOXING = NO` — are applied by a single idempotent script invoked via a `just` recipe, plus a `just` drift-check recipe that exits non-zero when the generated Xcode project is missing any patch.
- `apps/identity-wallet/CLAUDE.md` documents the de-Nixed workflow (the shared env script, the `just ios-*` entry points, the surviving patches). Manual prose-only pbxproj instructions and the hardcoded-path troubleshooting entries are removed or replaced by references to the script.
- The two novel macOS/Xcode bugs are documented **locally** (each with a minimal reproduction and the exact workaround), so they can be filed/PR'd upstream manually later. The `swift-rs` patch comment, the post-init script, and the docs reference this local record with a "remove when fixed upstream" note.
- The native SwiftUI-shell-over-Rust-core migration is captured as a trigger-gated decision record (trigger: background PLC monitoring becomes a hard requirement) and is explicitly **not** implemented by this plan.

## Acceptance Criteria

### denix-ios-build.AC1: No hardcoded toolchain paths; cc-wrapper conflicts resolved dynamically
- **denix-ios-build.AC1.1 Success:** `cargo tauri ios build --debug` (or `cargo tauri ios dev`) produces a runnable Simulator build from the devenv shell, with node/pnpm/cargo-tauri still Nix-provided.
- **denix-ios-build.AC1.2 Success:** `apps/identity-wallet/src-tauri/.cargo/config.toml` is deleted; the iOS + host overrides live in one committed `ios-env.sh` derived from `xcrun`/`xcode-select`. `grep -r "/Applications/Xcode" apps/ devenv.nix` returns nothing.
- **denix-ios-build.AC1.3 Success:** Build completes without `clang: error: invalid argument '-mmacos-version-min=…' not allowed with '-mios-simulator-version-min=…'`.
- **denix-ios-build.AC1.4 Success:** Build completes without `ld: library not found for -liconv` (host proc-macro link).
- **denix-ios-build.AC1.5 Success:** Build completes without `ld: framework not found UIKit` (iOS-sim final link).
- **denix-ios-build.AC1.6 Edge:** Switching the active Xcode via `xcode-select` (or an Xcode update that changes the toolchain path) does not require editing any committed file.

### denix-ios-build.AC2: Nix server build remains intact
- **denix-ios-build.AC2.1 Success:** Inside the Nix shell, `just build` (`cargo build --workspace`) succeeds, including the host build of `identity-wallet` + `security-framework`.
- **denix-ios-build.AC2.2 Success:** `just test` and `just clippy` pass inside the Nix shell.
- **denix-ios-build.AC2.3 Success:** `nix build .#relay --accept-flake-config` succeeds.
- **denix-ios-build.AC2.4 Failure-guard:** If moving the host overrides into `ios-env.sh` breaks the in-Nix host build, a minimal host-only fix is captured (not a restored iOS-override config file), after which AC2.1 passes.

### denix-ios-build.AC3: Surviving patches automated + drift detection
- **denix-ios-build.AC3.1 Success:** After a fresh `cargo tauri ios init`, `just ios-postinit` yields a project that builds via `just ios-build`.
- **denix-ios-build.AC3.2 Success:** `just ios-postinit` is idempotent — running it twice produces no further changes and does not error.
- **denix-ios-build.AC3.3 Success:** `just ios-check` exits 0 when all three patches (swift-rs wiring, Run Script PATH+source, `ENABLE_USER_SCRIPT_SANDBOXING = NO`) are present.
- **denix-ios-build.AC3.4 Failure:** `just ios-check` exits non-zero and names the missing patch when any is absent (e.g. immediately after `cargo tauri ios init`, before `ios-postinit`).
- **denix-ios-build.AC3.5 Success:** The Xcode Run Script "Build Rust Code" phase and `just ios-build` resolve the toolchain identically — both source `ios-env.sh` (single source of truth, no divergence).

### denix-ios-build.AC4: Documentation reflects the de-Nixed workflow
- **denix-ios-build.AC4.1 Success:** `apps/identity-wallet/CLAUDE.md` documents `ios-env.sh` and the `just ios-*` workflow.
- **denix-ios-build.AC4.2 Success:** No doc instructs editing `.cargo/config.toml` or hardcoding an Xcode path; obsolete cc-wrapper troubleshooting entries are removed or marked historical.
- **denix-ios-build.AC4.3 Success:** "Last verified"/"Last updated" dates are bumped on every edited CLAUDE.md.

### denix-ios-build.AC5: Upstream bugs documented locally (for later manual filing)
- **denix-ios-build.AC5.1 Success:** A local record documents both bugs — swift-rs `sandbox_apply` EPERM on macOS 26, and Xcode user-script-sandbox blocking Cargo — each with a minimal reproduction and the exact workaround applied.
- **denix-ios-build.AC5.2 Success:** The swift-rs patch comment, the `ios-postinit` script, and `CLAUDE.md` reference this local record with a "remove when fixed upstream" note.

### denix-ios-build.AC6: Migration decision record (documentation only)
- **denix-ios-build.AC6.1 Success:** A decision record states the SwiftUI-shell-over-Rust-core migration, its trigger (background PLC monitoring becomes a hard requirement), and "port the shell, never the crypto."
- **denix-ios-build.AC6.2 Success (negative):** No SwiftUI/UniFFI/FFI code is added by this plan; the Tauri dependency and app behavior are unchanged.

## Glossary

- **Nix / devenv**: Nix is a reproducible package manager that pins exact tool versions in a flake; devenv is a developer-environment layer on top of Nix that provides a per-project shell with all tools pre-installed. In this project, `devenv.nix` declares all tools and `direnv` activates the shell automatically on `cd`.
- **cc-wrapper**: Nix's compiler wrapper script that replaces the system compiler (`clang`) with a Nix-managed one that injects flags like `-mmacos-version-min`, `--sysroot`, and `-L` pointing at Nix's own SDK stubs. These injected flags are correct for native macOS builds but conflict with iOS cross-compilation.
- **Tauri / cargo tauri ios**: Tauri is a framework for building desktop and mobile apps with a Rust backend and a web frontend. `cargo tauri ios dev`/`build` is the Tauri CLI command that orchestrates the iOS build: it invokes Cargo for the Rust side, SwiftPM for the Swift glue, and Xcode for the final app bundle.
- **xcrun / xcode-select**: Apple command-line tools for resolving Xcode toolchain paths at runtime. `xcrun -f clang` finds the active Xcode's clang; `xcrun --sdk iphonesimulator --show-sdk-path` returns the current Simulator SDK path; `xcode-select -p` returns the active Xcode developer directory. Using these instead of hardcoded paths makes the build resilient to Xcode updates and `xcode-select --switch`.
- **DEVELOPER_DIR**: An environment variable Apple tools use to locate the active Xcode installation (e.g. `/Applications/Xcode.app/Contents/Developer`). Nix's Darwin build hooks overwrite it to a stub SDK; the project currently re-exports the real path in `devenv.nix`'s `enterShell`, hardcoded. The plan replaces the hardcoded value with a `xcode-select -p`-derived one in `ios-env.sh`.
- **swift-rs**: A Rust crate that lets Rust code call Swift code (and vice versa) during the build. This project uses a vendored fork because the upstream version calls `sandbox_apply()` during SwiftPM manifest compilation, which fails with `EPERM` on macOS 26. The fork adds `--disable-sandbox` to the SwiftPM invocation.
- **project.pbxproj**: The Xcode project file (inside `src-tauri/gen/apple/`) that defines build targets, build phases, and build settings. Tauri regenerates this file on `cargo tauri ios init`, so it is gitignored and must be re-patched after every regeneration. Two patches are applied: prepending the devenv tool directories to PATH in the "Build Rust Code" Run Script phase, and sourcing `ios-env.sh` in that same phase.
- **ENABLE_USER_SCRIPT_SANDBOXING**: An Xcode build setting (introduced in Xcode 14, enforced more strictly on macOS 26) that sandboxes user-defined Run Script phases. When set to `YES`, it blocks Cargo's directory walk (`readdir`), causing the build to fail. Setting it to `NO` disables the sandbox for Run Script phases.
- **Secure Enclave**: Apple's dedicated security coprocessor (present on iPhone and Apple Silicon Macs) used for hardware-backed key storage. Referenced as context for why the Rust crypto core must stay in Rust and must not be rewritten in Swift during the deferred migration.
- **PLC monitoring / plc_monitor.rs**: PLC refers to the AT Protocol's PLC directory, which tracks DID document history. `plc_monitor.rs` polls the PLC directory for changes and emits alerts. It runs as a foreground Tokio interval loop, which iOS suspends when the app is backgrounded — the motivation for the deferred SwiftUI migration decision record.
- **UniFFI**: Mozilla's framework for generating FFI (Foreign Function Interface) bindings between Rust and other languages (Swift, Kotlin, Python). The mechanism the deferred SwiftUI-shell migration would use to expose the Rust core to a native Swift host app, without rewriting the Rust logic.
- **rustup target / sysroot**: `rustup target add aarch64-apple-ios-sim` installs the Rust standard library pre-compiled for a specific target triple. The sysroot is the corresponding directory of pre-built `std` and platform libraries Cargo links against when cross-compiling for that target.

## Architecture

### Diagnosis

The identity-wallet iOS build feels brittle because of a single root cause: **the Nix devenv toolchain and Apple's Xcode toolchain are forced to coexist in one build, and they disagree about the compiler, linker, and SDK.** A multi-agent re-evaluation cataloged ten distinct workarounds; six are Nix↔Apple collisions and zero are caused by Tauri's application model. Tauri is merely the orchestrator standing at the seam (it drives `cargo` + SwiftPM + Xcode together), so it inherits the pain.

The sharpest, most brittle part is not "Nix is involved" — it is the **hardcoded `/Applications/Xcode.app/...` paths** in `.cargo/config.toml` and `devenv.nix`, which break whenever Xcode moves, updates, or is selected via `xcode-select`. This plan removes every hardcoded path and consolidates the unavoidable cc-wrapper overrides into one `xcrun`-derived env script, while keeping Nix as the single provider of node/pnpm/cargo-tauri/rustup.

### Chosen approach: hybrid de-Nix (keep Nix as tool provider)

A full exit from Nix (provisioning node/pnpm/cargo-tauri outside Nix and building from a plain terminal) is the *maximally* clean end state, but it trades away Nix-pinned JS tooling. The chosen approach keeps Nix authoritative for all tools and the dev shell, and instead attacks the actual brittleness — hardcoded paths and manual, undocumented patches:

1. **One committed env script** — `apps/identity-wallet/scripts/ios-env.sh` (exact name TBD in implementation) computes the iOS + host toolchain overrides (`CC_*`, `AR_*`, target linkers, host SDK `-L`, `DEVELOPER_DIR`) entirely from `xcrun -f`, `xcrun --sdk … --show-sdk-path`, and `xcode-select -p`. No literal Xcode paths.
2. **Two consumers, one source** — the devenv `enterShell` sources `ios-env.sh` (so a CLI `cargo tauri ios dev`/`build` from the shell is correct), and the post-init script patches the Xcode `project.pbxproj` Run Script phase to source it too (so the Xcode-driven compile sees the same overrides). This is what lets `.cargo/config.toml` be **deleted** rather than merely de-hardcoded: the on-disk config file existed only because the Xcode Run Script can't see shell env — sourcing the shared script in the Run Script removes that need.
3. **Nix unchanged for tools** — `pkgs.cargo-tauri`, `pkgs.nodejs_22`, `pkgs.pnpm`, `pkgs.rustup` stay in `devenv.nix`. No `.nvmrc`, no Corepack pin, no `cargo install tauri-cli`.

### What changes vs. what survives

The current toolchain is already rustup-managed (`languages.rust` is deliberately absent from `devenv.nix`). The brittleness comes from the Nix cc-wrapper (`.devenv/profile/bin/clang`) being the default compiler/linker and from hardcoded Xcode paths. The hybrid has a precise, verified effect:

| Workaround | Location | Root cause | After hybrid de-Nix |
|---|---|---|---|
| `.cargo/config.toml` CC/AR overrides (ios, ios-sim, darwin) | `apps/identity-wallet/src-tauri/.cargo/config.toml:16-21` | Nix cc-wrapper injects `-mmacos-version-min` on iOS compiles | **Deleted**; overrides move to `ios-env.sh` (xcrun-derived) |
| `.cargo/config.toml` host linker + `-L .../usr/lib` | same file `:39-42` | Nix apple-sdk stub omits `/usr/lib` stubs (`libiconv.tbd`) | **Deleted**; host SDK `-L` derived via `xcrun --show-sdk-path` |
| `.cargo/config.toml` iOS sim/device linker | same file `:44-48` | Nix cc-wrapper injects macOS sysroot on iOS link (UIKit not found) | **Deleted**; linker set to xcrun-resolved clang |
| `DEVELOPER_DIR` re-export (hardcoded) | `devenv.nix:33-38` | Nix Darwin hooks clobber `DEVELOPER_DIR` | **De-hardcoded**: derived via `xcode-select -p` in `ios-env.sh`, still exported in-shell |
| `swift-rs` `--disable-sandbox` fork | `apps/identity-wallet/swift-rs-patch/src-rs/build.rs:264`, wired via `Cargo.toml:100-101` | macOS 26 `sandbox_apply()` EPERM in SwiftPM (not Nix) | **Survives** → scripted + local bug doc |
| pbxproj PATH prepend | `apps/identity-wallet/CLAUDE.md:177-189` | Xcode Run Script phase doesn't inherit cargo's PATH (not Nix) | **Survives** → scripted (also sources `ios-env.sh`) |
| pbxproj `ENABLE_USER_SCRIPT_SANDBOXING = NO` | `apps/identity-wallet/CLAUDE.md:191-207` | macOS 26 + Xcode 14+ sandbox blocks Cargo `readdir` (not Nix) | **Survives** → scripted |

Outcome: every hardcoded path is gone, `.cargo/config.toml` is deleted, the overrides live in one xcrun-derived script with a single source of truth, and the three survivors (macOS/Xcode issues independent of Nix) are automated and documented for later upstream filing. The residual, relative to a full Nix-free build: the build still runs in the devenv shell and a (now robust, `xcode-select`-derived) `DEVELOPER_DIR` is still exported. Both are harmless; full exit from Nix remains available later if desired.

### Surviving-patch automation

A single idempotent script (under `apps/identity-wallet/scripts/`) re-applies the survivors after every `cargo tauri ios init` (which regenerates the gitignored `src-tauri/gen/`): verify the `swift-rs` patch is wired, patch the `project.pbxproj` Run Script build phase to (a) prepend the devenv tool dirs to PATH and (b) source `ios-env.sh`, and set `ENABLE_USER_SCRIPT_SANDBOXING = NO`. A companion drift-check inspects `project.pbxproj` and exits non-zero (naming the missing patch) if any is absent, so the failure mode is a loud check rather than a silent broken build. Both are exposed as `just` recipes. There is no GitHub Actions CI in this repo, so the drift check is a `just` recipe (runnable locally and from any future CI), not a workflow file.

### Deferred: native SwiftUI shell over the Rust core

De-Nixing does not improve background execution. `plc_monitor.rs` runs a foreground `tokio::time::interval` that iOS suspends on backgrounding; true periodic checks need Apple's `BGTaskScheduler`, reachable only from native Swift. The validated recommendation is to migrate to a native SwiftUI shell over the same Rust core (via UniFFI) **only when background PLC monitoring becomes a hard requirement** — and even then to port the shell, never the crypto. This plan documents that trigger and the low-friction migration path (the monitoring logic is already cleanly separated: only `run_monitoring_loop` and `emit_if_alerts` touch Tauri) as a decision record. No migration code is written here.

## Existing Patterns

- **rustup-not-Nix-rust** is already the project's decision (`devenv.nix:16-19`, with `languages.rust` intentionally absent). This plan keeps rustup and Nix tooling but removes the hardcoded Xcode coupling layered on top of them.
- **`Justfile` task runner** already centralizes developer commands (`check`, `build`, `test`, `fmt`, `clippy`, `nix-build`, `ci`, `nix-check`). New `ios-*` recipes follow the same one-line-recipe-with-comment style.
- **`devenv.nix` `enterShell`** already runs shell logic at shell entry (the rustup install check, the `DEVELOPER_DIR` re-export). Sourcing `ios-env.sh` from `enterShell` extends an existing pattern rather than introducing a new mechanism.
- **`src-tauri/gen/` is gitignored** and regenerated per machine by `cargo tauri ios init` (`apps/identity-wallet/CLAUDE.md:140`, `:175`). Patch automation must target this regenerated, untracked directory — hence an idempotent script rather than a committed patch.
- **Cargo `[patch.crates-io]`** already wires the vendored `swift-rs` fork (`Cargo.toml:100-101`). This plan keeps that mechanism and adds a local-bug-doc link so it can be retired cleanly.
- **`flake.nix` `buildDepsOnly` is already scoped** to relay-related crates only (`flake.nix:46-48`), explicitly excluding `identity-wallet` because Tauri's native deps don't build under Nix. Removing the iOS app's hardcoded toolchain coupling is consistent with this existing boundary.
- **CLAUDE.md as the developer runbook** — the project documents setup/troubleshooting in `apps/identity-wallet/CLAUDE.md`, with a "Last verified" freshness-date convention. Updates land there.

## Implementation Phases

<!-- START_PHASE_1 -->
### Phase 1: Centralize the toolchain in a single xcrun-derived env script
**Goal:** Make the iOS app build with zero hardcoded toolchain paths, with `.cargo/config.toml` deleted, while node/pnpm/cargo-tauri/rustup stay Nix-provided — and prove the Nix server build is unaffected.

**Components:**
- `apps/identity-wallet/scripts/ios-env.sh` (new) — derives `CC_aarch64_apple_ios{,_sim}`, `CC_aarch64_apple_darwin`, matching `AR_*`, the per-target linkers, the host SDK `-L`, and `DEVELOPER_DIR` from `xcrun`/`xcode-select`. No literal Xcode paths.
- `apps/identity-wallet/src-tauri/.cargo/config.toml` — deleted (its `RUST_TEST_THREADS=1` `[env]` entry, if still wanted, moves to `ios-env.sh` or devenv).
- `devenv.nix` — replace the hardcoded `DEVELOPER_DIR` re-export (`:33-38`) with `source`-ing `ios-env.sh`; keep `pkgs.cargo-tauri`/`nodejs_22`/`pnpm`/`rustup` and the rustup install check.

**Dependencies:** None (first phase).

**Done when:**
- `cargo tauri ios build --debug` (or `cargo tauri ios dev`) succeeds for `aarch64-apple-ios-sim` from the devenv shell, with `.cargo/config.toml` deleted and no cc-wrapper errors.
- `grep -r "/Applications/Xcode" apps/ devenv.nix` returns nothing.
- Inside the Nix shell, `just build`, `just test`, `just clippy`, and `nix build .#relay --accept-flake-config` still pass (host `security-framework` C build links). Critical verification risk: confirm deleting `.cargo/config.toml` and moving the host overrides into `ios-env.sh` (sourced by `enterShell`) does not break the in-Nix host build of `identity-wallet`/`security-framework`.
<!-- END_PHASE_1 -->

<!-- START_PHASE_2 -->
### Phase 2: De-Nixed build entry points + idempotent patch automation
**Goal:** Turn the build and the three surviving patches into reproducible `just` recipes so no step is tribal knowledge, and make the Xcode-driven build use the same toolchain source as the CLI build.

**Components:**
- `apps/identity-wallet/scripts/ios-postinit.sh` (or equivalent) — idempotent: verify the `swift-rs` patch is wired; patch the `project.pbxproj` Run Script "Build Rust Code" phase to prepend the devenv tool dirs to PATH **and** `source` `ios-env.sh`; set `ENABLE_USER_SCRIPT_SANDBOXING = NO`. Safe to re-run.
- `apps/identity-wallet/scripts/ios-check.sh` (or a `just`-inline check) — inspect `src-tauri/gen/apple/.../project.pbxproj`; exit non-zero (naming the missing patch) if any of the three is absent.
- `Justfile` recipes: `ios-dev`, `ios-build`, `ios-postinit`, `ios-check`. Follow existing Justfile style.

**Dependencies:** Phase 1 (a working toolchain source to wrap and to source from the Run Script).

**Done when:** `just ios-postinit` applied to a freshly `cargo tauri ios init`-generated project yields a successful `just ios-build`; running `ios-postinit` twice is a no-op; `just ios-check` passes on a patched project and fails (non-zero) on an unpatched one; an Xcode-driven build and `just ios-build` resolve the toolchain identically (both via `ios-env.sh`).
<!-- END_PHASE_2 -->

<!-- START_PHASE_3 -->
### Phase 3: Documentation overhaul
**Goal:** `apps/identity-wallet/CLAUDE.md` reflects the de-Nixed reality so a fresh machine setup follows the script, not prose.

**Components:**
- Rewrite "First-Time Setup", "Xcode build phase PATH", "Disable user script sandboxing", and the cc-wrapper "Troubleshooting" entries (`apps/identity-wallet/CLAUDE.md:157-210`, `:378-427`) to describe: `ios-env.sh`, the `just ios-*` workflow, and the surviving patches applied by `just ios-postinit`.
- Remove or mark-historical the troubleshooting entries that no longer apply (the three cc-wrapper failures; the hardcoded `DEVELOPER_DIR` entry).
- Update the root `CLAUDE.md` mobile section and `devenv.nix` comments where they reference the old hardcoded iOS setup. Bump the "Last verified" dates.

**Dependencies:** Phases 1-2 (document the final shape).

**Done when:** A reader following only `CLAUDE.md` can set up and build the iOS app on a fresh Mac without referring to this design plan; no doc instructs editing `.cargo/config.toml` or hardcoding an Xcode path.
<!-- END_PHASE_3 -->

<!-- START_PHASE_4 -->
### Phase 4: Local upstream-bug documentation
**Goal:** Make the two surviving non-Nix workarounds deletable later by documenting them precisely now — so the user can file the issue/PR upstream manually on their own schedule.

**Components:**
- A local record (e.g. `docs/` note or a clearly-marked section) for both bugs: (1) `swift-rs` `sandbox_apply()` EPERM on macOS 26 during SwiftPM manifest compilation — reference `apps/identity-wallet/swift-rs-patch/src-rs/build.rs:262-264`; (2) Xcode user-script-sandbox (`ENABLE_USER_SCRIPT_SANDBOXING = YES`) blocking Cargo's directory walk on macOS 26. Each entry includes a minimal reproduction and the exact workaround applied.
- Link this local record from the `swift-rs` patch comment, the `ios-postinit` script, and `CLAUDE.md`, each with a "remove when fixed upstream" note.

**Dependencies:** Phases 1-2 (so the reproductions and exact patch points are settled). No external action (no issues filed) is required for this phase to be done.

**Done when:** The local record exists with minimal reproductions for both bugs and is referenced from the code/docs.
<!-- END_PHASE_4 -->

<!-- START_PHASE_5 -->
### Phase 5: Native SwiftUI migration decision record (documentation only)
**Goal:** Record the validated "destination" architecture and its trigger so the decision is captured, without building it.

**Components:**
- A decision-record note (in `docs/`, referenced from `CLAUDE.md`): migrate to a native SwiftUI shell over the same Rust core (UniFFI) **only** when background PLC monitoring becomes a hard requirement; port the shell, never the crypto core; note the migration is pre-de-risked because only `run_monitoring_loop` and `emit_if_alerts` in `plc_monitor.rs` touch Tauri.

**Dependencies:** None (independent). Explicitly **not** an implementation phase for the migration itself — no FFI, no SwiftUI code.

**Done when:** The decision and its concrete trigger are written down and discoverable from the mobile docs.
<!-- END_PHASE_5 -->

## Additional Considerations

**Verification requires the user's Mac.** Phases 1-2 can only be fully verified on macOS with Xcode and a Simulator installed; `cargo tauri ios build` is slow and cannot run in CI here. Executors must run the build/verification steps on the developer machine and paste output as evidence.

**Reversibility.** Every change is reversible: restoring `apps/identity-wallet/src-tauri/.cargo/config.toml` and the `devenv.nix` re-export returns to the prior build. Validate the new `ios-env.sh` path with a real Simulator build *before* deleting the old config (delete last, after the new path is proven).

**The Xcode Run Script is the subtle part.** `cargo tauri ios dev` builds Rust via Xcode's Run Script phase, which does not inherit the devenv shell environment. The shared `ios-env.sh` must therefore be sourced by both `enterShell` (for CLI builds) and the patched Run Script (for Xcode-driven builds), or the two paths will diverge. This is the reason `.cargo/config.toml` could be deleted only after Phase 2 wires the Run Script to source the script.

**Full Nix-free build remains a future option.** If the in-shell residual (build runs in devenv; `DEVELOPER_DIR` exported) ever becomes undesirable, provisioning node/pnpm/cargo-tauri outside Nix and running from a plain terminal would shed it. Not pursued now, by preference to keep Nix as the single tool provider.

**No CI exists.** There is no `.github/workflows/`. The drift check is a `just` recipe so it is useful locally now and droppable into CI later without rework.

**Scope boundary.** This plan does not change app behavior, the frontend, the Rust core logic, or the Tauri dependency. It changes only *how the iOS app's toolchain is resolved* and *how the surviving patches are managed*, plus documentation and a decision record.
