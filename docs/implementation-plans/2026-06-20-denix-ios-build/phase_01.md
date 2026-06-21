# De-Nix the iOS Build — Implementation Plan

**Goal:** Centralize the Apple toolchain in a single `xcrun`-derived env script, delete the hardcoded `src-tauri/.cargo/config.toml`, and keep Nix as the sole provider of node/pnpm/cargo-tauri/rustup.

**Architecture:** A committed `apps/identity-wallet/scripts/ios-env.sh` derives the C compiler, archiver, per-target linkers, host SDK lib path, and `DEVELOPER_DIR` from `xcrun`/`xcode-select` (no literal Xcode paths). It is sourced by `devenv.nix`'s `enterShell` (for CLI builds) and — in Phase 2 — by the patched Xcode "Build Rust Code" Run Script phase (which does not inherit the shell environment). With overrides supplied dynamically, the hardcoded config file is removed.

**Tech Stack:** Nix + devenv, rustup (iOS targets), Cargo cross-compilation env vars (`CC_<target>`, `AR_<target>`, `CARGO_TARGET_<TRIPLE>_LINKER`, `CARGO_TARGET_<TRIPLE>_RUSTFLAGS`), `xcrun`/`xcode-select`, Tauri v2 iOS.

**Scope:** Phase 1 of 5 from `docs/design-plans/2026-06-20-denix-ios-build.md`.

**Codebase verified:** 2026-06-20 (codebase-investigator + internet-researcher).

> **Platform note:** Every build/verification step in this phase that compiles for iOS **must run on the developer's macOS machine with Xcode + an iOS Simulator installed**. These steps are marked **[developer-machine only]**. They cannot run in this repo's CI (there is none) or in any headless/Linux environment.

> **Key verified facts (do not re-derive):**
> - `apps/identity-wallet/src-tauri/.cargo/config.toml` exists and sets `[env]` `RUST_TEST_THREADS="1"`, `CC_*`/`AR_*` (lines 14-21) and `[target.*]` `linker`/`rustflags` (lines 39-48), all hardcoded to `/Applications/Xcode.app/...`.
> - There is **no** `.cargo/config.toml` at the repo root and **none** in `$CARGO_HOME` (`.devenv/state/cargo`). Therefore a root-level `cargo build --workspace` does **not** currently read `src-tauri/.cargo/config.toml` — the host `aarch64-apple-darwin` overrides only apply when cargo runs from inside `src-tauri/` (e.g. via `cargo tauri ios`).
> - `devenv.nix` `enterShell` is lines 33-44; the hardcoded `DEVELOPER_DIR` export is line 38; `RUSTUP_HOME`/`CARGO_HOME` are lines 20-21; tool packages (`cargo-tauri`, `nodejs_22`, `pnpm`, `rustup`) are lines 3-12.
> - Cargo env-var equivalents are authoritative and override config files: `CC_<target>`/`AR_<target>` (cc-crate convention, read by build scripts) and `CARGO_TARGET_<TRIPLE>_LINKER` / `CARGO_TARGET_<TRIPLE>_RUSTFLAGS` (triple uppercased, `-`→`_`).
> - Xcode Run Script phases do **not** inherit the calling shell's environment (handled in Phase 2).

---

## Acceptance Criteria Coverage

This phase implements and verifies:

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

**Verifies (this phase):** denix-ios-build.AC1.1, AC1.2, AC1.3, AC1.4, AC1.5, AC1.6, AC2.1, AC2.2, AC2.3, AC2.4.

> These are **infrastructure** criteria, verified operationally (build/grep succeed), not by unit tests. Do not invent unit tests for this phase.

---

<!-- START_TASK_1 -->
### Task 1: Create the toolchain env script `ios-env.sh`

**Files:**
- Create: `apps/identity-wallet/scripts/ios-env.sh` (the `scripts/` directory does not exist yet — create it)

**Step 1: Create the directory and file**

Create `apps/identity-wallet/scripts/ios-env.sh` with exactly this content:

```bash
#!/usr/bin/env bash
# ios-env.sh — derive the Apple toolchain for cross-compiling identity-wallet's
# Rust code to iOS, with ZERO hardcoded paths.
#
# Sourced by:
#   1. devenv.nix `enterShell` (CLI `cargo tauri ios dev`/`build`), and
#   2. the Xcode "Build Rust Code" Run Script phase (patched by ios-postinit.sh in
#      Phase 2) — that phase does NOT inherit the calling shell's environment.
#
# Everything is resolved via `xcrun`/`xcode-select`, so the build follows whatever
# Xcode `xcode-select` points at (survives Xcode moves, updates, beta switches).
#
# This file is SOURCED, never executed: it must not call `exit` and must not enable
# `set -e` (that would leak into the caller). Safe to source repeatedly.

# If Apple tools are missing (e.g. a non-mac shell), do nothing — never break the
# caller's shell just because it was sourced somewhere without Xcode.
if ! command -v xcrun >/dev/null 2>&1 || ! command -v xcode-select >/dev/null 2>&1; then
  return 0 2>/dev/null || true
fi

# Active Xcode developer dir (Nix's Darwin hooks otherwise point this at a stub SDK).
_ezpds_dev_dir="$(xcode-select -p 2>/dev/null || true)"
if [ -n "${_ezpds_dev_dir}" ]; then
  export DEVELOPER_DIR="${_ezpds_dev_dir}"
fi

# Unwrapped Apple clang/ar — bypasses the Nix cc-wrapper, which injects
# -mmacos-version-min and the wrong sysroot for iOS targets.
_ezpds_clang="$(xcrun -f clang 2>/dev/null || true)"
_ezpds_ar="$(xcrun -f ar 2>/dev/null || true)"

if [ -n "${_ezpds_clang}" ]; then
  # iOS TARGET overrides — always safe to export: no server crate targets iOS, so
  # these never affect a relay / `cargo build --workspace` host build.
  export CC_aarch64_apple_ios_sim="${_ezpds_clang}"
  export CC_aarch64_apple_ios="${_ezpds_clang}"
  export CARGO_TARGET_AARCH64_APPLE_IOS_SIM_LINKER="${_ezpds_clang}"
  export CARGO_TARGET_AARCH64_APPLE_IOS_LINKER="${_ezpds_clang}"
fi
if [ -n "${_ezpds_ar}" ]; then
  export AR_aarch64_apple_ios_sim="${_ezpds_ar}"
  export AR_aarch64_apple_ios="${_ezpds_ar}"
fi

# HOST (aarch64-apple-darwin) overrides are needed ONLY while cross-building the iOS
# app — its host-side proc-macros and security-framework C build otherwise hit the Nix
# cc-wrapper (-mmacos-version-min) and the Nix apple-sdk stub (missing /usr/lib stubs
# like libiconv.tbd). They are GATED on EZPDS_IOS_BUILD so ordinary in-shell builds
# (`cargo build --workspace`, `cargo run -p relay`) keep using the Nix toolchain exactly
# as before — this is what makes AC2 (server build intact) true BY CONSTRUCTION. The iOS
# build entry points set EZPDS_IOS_BUILD=1: the `just ios-dev`/`ios-build` recipes and
# the injected Xcode "Build Rust Code" Run Script block (both in Phase 2).
if [ -n "${EZPDS_IOS_BUILD:-}" ]; then
  if [ -n "${_ezpds_clang}" ]; then
    export CC_aarch64_apple_darwin="${_ezpds_clang}"
    export CARGO_TARGET_AARCH64_APPLE_DARWIN_LINKER="${_ezpds_clang}"
  fi
  if [ -n "${_ezpds_ar}" ]; then
    export AR_aarch64_apple_darwin="${_ezpds_ar}"
  fi
  _ezpds_macos_sdk="$(xcrun --sdk macosx --show-sdk-path 2>/dev/null || true)"
  if [ -n "${_ezpds_macos_sdk}" ]; then
    export CARGO_TARGET_AARCH64_APPLE_DARWIN_RUSTFLAGS="-L ${_ezpds_macos_sdk}/usr/lib"
  fi
fi

unset _ezpds_dev_dir _ezpds_clang _ezpds_ar _ezpds_macos_sdk
```

**Step 2: Make it executable** (harmless for a sourced file; keeps it runnable for ad-hoc debugging)

Run: `chmod +x apps/identity-wallet/scripts/ios-env.sh`

**Step 3: Verify it parses and sets the expected vars [developer-machine only]**

Run from the repo root inside the devenv shell:
```bash
bash -n apps/identity-wallet/scripts/ios-env.sh   # syntax check, any machine
command -v shellcheck >/dev/null && shellcheck -s bash apps/identity-wallet/scripts/ios-env.sh  # stronger check, if available
# On macOS, confirm it resolves real paths. The host (darwin) overrides only export
# when EZPDS_IOS_BUILD is set, so set it for this check:
( export EZPDS_IOS_BUILD=1; source apps/identity-wallet/scripts/ios-env.sh && \
  echo "DEVELOPER_DIR=$DEVELOPER_DIR" && \
  echo "CC_ios_sim=$CC_aarch64_apple_ios_sim" && \
  echo "linker_darwin=$CARGO_TARGET_AARCH64_APPLE_DARWIN_LINKER" && \
  echo "darwin_rustflags=$CARGO_TARGET_AARCH64_APPLE_DARWIN_RUSTFLAGS" )
# And confirm the host overrides are ABSENT without the flag (AC2 by construction):
( source apps/identity-wallet/scripts/ios-env.sh && \
  echo "darwin_linker_without_flag=[${CARGO_TARGET_AARCH64_APPLE_DARWIN_LINKER:-}]" )
```
Expected: `bash -n` prints nothing (exit 0, any machine). On macOS with the flag, each value is a real path under the active Xcode (e.g. `/Applications/Xcode.app/Contents/Developer/...` or a CommandLineTools/beta path), NOT empty. Without the flag, `darwin_linker_without_flag=[]` (empty) — proving the host override never leaks into ordinary builds. `shellcheck`, if present, reports no errors.

**Step 4: Commit**
```bash
git add apps/identity-wallet/scripts/ios-env.sh
git commit -m "build(identity-wallet): add xcrun-derived ios-env.sh toolchain script"
```
Confirm the executable bit was committed: `git ls-files -s apps/identity-wallet/scripts/ios-env.sh` shows mode `100755` (so the ad-hoc-debugging `./ios-env.sh` use works on a fresh clone).
<!-- END_TASK_1 -->

<!-- START_TASK_2 -->
### Task 2: Source `ios-env.sh` from devenv `enterShell` and drop the hardcoded `DEVELOPER_DIR`

**Files:**
- Modify: `devenv.nix:33-44` (the `enterShell` block)

**Step 1: Replace the hardcoded `DEVELOPER_DIR` export with sourcing the script**

In `devenv.nix`, the current `enterShell` (lines 33-44) is:
```nix
  enterShell = ''
    # Nix's Darwin setup hooks (xcbuild, apple-sdk) override DEVELOPER_DIR to a
    # Nix SDK stub that has no runtime tools. Re-export here so this shell and all
    # processes it spawns (cargo tauri ios dev, xcodebuild, xcrun, simctl) use the
    # real Xcode installation. enterShell runs after all Nix hooks, so it wins.
    export DEVELOPER_DIR="/Applications/Xcode.app/Contents/Developer"
    export PATH="$CARGO_HOME/bin:$PATH"
    if ! "$CARGO_HOME/bin/cargo" --version > /dev/null 2>&1; then
      echo "Installing Rust toolchain (first time — reads rust-toolchain.toml)…"
      rustup toolchain install
    fi
  '';
```

Replace it with:
```nix
  enterShell = ''
    export PATH="$CARGO_HOME/bin:$PATH"
    # Apple toolchain for iOS cross-compilation, derived dynamically via xcrun/
    # xcode-select (no hardcoded Xcode paths). Also sets DEVELOPER_DIR, which Nix's
    # Darwin hooks otherwise clobber to a stub SDK. enterShell runs after all Nix
    # hooks, so this wins. Same script is sourced by the Xcode Run Script phase
    # (patched by apps/identity-wallet/scripts/ios-postinit.sh) so CLI and
    # Xcode-driven builds resolve the toolchain identically.
    if [ -f "${config.devenv.root}/apps/identity-wallet/scripts/ios-env.sh" ]; then
      source "${config.devenv.root}/apps/identity-wallet/scripts/ios-env.sh"
    fi
    if ! "$CARGO_HOME/bin/cargo" --version > /dev/null 2>&1; then
      echo "Installing Rust toolchain (first time — reads rust-toolchain.toml)…"
      rustup toolchain install
    fi
  '';
```

(Note: `${config.devenv.root}` is already used elsewhere in `devenv.nix` — lines 20-21, 24-26 — so it is in scope here.)

**Step 2: Verify the shell re-enters cleanly and the vars are set [developer-machine only]**

Exit and re-enter the dev shell (or run `direnv reload`), then:
```bash
echo "$DEVELOPER_DIR"
echo "$CARGO_TARGET_AARCH64_APPLE_IOS_SIM_LINKER"
```
Expected: both are non-empty real paths under the active Xcode. No errors during shell entry.

**Step 3: Commit**
```bash
git add devenv.nix
git commit -m "build: source ios-env.sh from devenv enterShell; drop hardcoded DEVELOPER_DIR"
```
<!-- END_TASK_2 -->

<!-- START_TASK_3 -->
### Task 3: Handle `RUST_TEST_THREADS`, then delete `.cargo/config.toml`

**Files:**
- Modify or delete: `apps/identity-wallet/src-tauri/.cargo/config.toml`

**Context:** The file's only non-toolchain setting is `[env] RUST_TEST_THREADS = "1"` (line 15), which serializes identity-wallet's Rust tests. Determine whether it is load-bearing before deleting, so test behavior doesn't silently change.

**Step 1: Determine if `RUST_TEST_THREADS=1` is load-bearing [developer-machine only]**

Run the identity-wallet backend tests **with** parallelism to see if they are safe to parallelize:
```bash
cargo test -p identity-wallet -- --test-threads=4
```
- If tests **pass**: `RUST_TEST_THREADS` is not required → proceed to Step 2a (full delete).
- If tests **fail/flake** (e.g. Keychain or shared-state contention): it is load-bearing → proceed to Step 2b (retain only that line).

**Step 2a: Full delete (if not load-bearing)**

Run: `git rm apps/identity-wallet/src-tauri/.cargo/config.toml`

(If `.cargo/` is now empty: `rmdir apps/identity-wallet/src-tauri/.cargo 2>/dev/null || true`.)

**Step 2b: Retain only the test-thread setting (if load-bearing)**

Overwrite `apps/identity-wallet/src-tauri/.cargo/config.toml` with exactly:
```toml
# Serialize identity-wallet's Rust tests (Keychain / shared-state contention).
# All toolchain overrides moved to scripts/ios-env.sh — this file intentionally
# contains NO hardcoded Xcode paths.
[env]
RUST_TEST_THREADS = "1"
```

> Reviewer/executor note: Step 2b leaves a `.cargo/config.toml` present, which technically diverges from AC1.2's literal "deleted." This is the deliberate, documented exception: it carries no toolchain/path content, only test serialization. The AC1.2 grep check (`/Applications/Xcode`) still passes. If the user prefers a fully deleted file, replace this with `serial_test` on the affected tests in a follow-up — out of scope here.

**Step 3: Commit**
```bash
git add -A apps/identity-wallet/src-tauri/.cargo/
git commit -m "build(identity-wallet): remove hardcoded .cargo/config.toml toolchain overrides"
```
<!-- END_TASK_3 -->

<!-- START_TASK_4 -->
### Task 4: Verify the de-Nixed build end-to-end and apply the host-build failure-guard if needed

**Files:** none (verification + conditional fix)

This task proves AC1 and AC2. All build steps are **[developer-machine only]**.

**Step 1: iOS Simulator build (AC1.1, AC1.3, AC1.4, AC1.5)** — from `apps/identity-wallet/` inside the devenv shell:
```bash
cargo tauri ios build --debug
```
Expected: completes and produces a Simulator build. Watch the log to confirm NONE of these appear:
- `-mmacos-version-min … not allowed with -mios-simulator-version-min` (AC1.3)
- `ld: library not found for -liconv` (AC1.4)
- `ld: framework not found UIKit` (AC1.5)

(If `src-tauri/gen/` does not exist yet on this machine, run `cargo tauri ios init` first, then `just ios-postinit` from Phase 2 — but for an isolated Phase 1 check, a direct `cargo build --target aarch64-apple-ios-sim -p identity-wallet` also exercises the toolchain overrides without the Xcode Run Script.)

**Step 2: No hardcoded paths remain (AC1.2, AC1.6)**
```bash
grep -rn "/Applications/Xcode" apps/ devenv.nix
```
Expected: no output (exit 1 from grep). The only Xcode reference allowed anywhere is via `xcrun`/`xcode-select` inside `ios-env.sh`.

**Step 3: Nix server build intact (AC2.1, AC2.2, AC2.3)** — from repo root inside the devenv shell:
```bash
just build      # cargo build --workspace (incl. host identity-wallet + security-framework)
just clippy     # cargo clippy --workspace -- -D warnings
just test       # cargo test --workspace
nix build .#relay --accept-flake-config
```
Expected: all succeed.

**Step 4: Confirm the host override does not leak to the relay/server build (AC2.4)**

This is satisfied **by construction**: in `ios-env.sh` the host (`aarch64-apple-darwin`) overrides are gated behind `EZPDS_IOS_BUILD`, which `enterShell` does **not** set — only the iOS build entry points do (the `just ios-dev`/`ios-build` recipes and the injected Xcode Run Script block, both Phase 2). The always-on iOS-*target* overrides are harmless to the relay because no server crate targets iOS. Verify in a normal dev shell (no iOS build):

```bash
env | grep -E 'AARCH64_APPLE_DARWIN' ; echo "darwin-overrides-exit=$?"
just build && just test && cargo build -p relay
```
Expected: `grep` prints nothing (`darwin-overrides-exit=1`), and the relay/workspace builds behave exactly as before de-Nixing (AC2.1, AC2.2). `nix build .#relay --accept-flake-config` is unaffected regardless, because it builds in a Nix sandbox that never sources `enterShell` (AC2.3).

If — contrary to design — the relay build regresses, the gated host override is NOT the cause (it isn't set here); investigate the always-on iOS-target vars, though no regression is expected. Do **not** restore the deleted iOS-override config file.

**Step 5: No new commit needed** unless the optional investigation above produced a change.

> **Cross-phase contract (do not drop):** AC2's by-construction guarantee depends on Phase 2 setting `EZPDS_IOS_BUILD=1` in BOTH the `just ios-dev`/`ios-build` recipes AND the injected Xcode Run Script block. If you change how the flag is set, keep all three in sync (this script's gate + the recipes + the Run Script injection), or the iOS build will lose its host override and AC1.4 (`-liconv`) will resurface.
<!-- END_TASK_4 -->

---

## Phase 1 Done When

- `cargo tauri ios build --debug` succeeds with no cc-wrapper errors (AC1.1, AC1.3–1.5) **[developer-machine]**.
- `grep -rn "/Applications/Xcode" apps/ devenv.nix` is empty (AC1.2, AC1.6).
- `just build`, `just clippy`, `just test`, `nix build .#relay` all pass in the Nix shell (AC2.1–2.3), with the AC2.4 guard applied only if needed.
- All changes committed.
