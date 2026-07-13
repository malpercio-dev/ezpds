# Test Requirements — De-Nix the iOS Build

**Design plan:** `docs/design-plans/2026-06-20-denix-ios-build.md`
**Implementation plan:** `docs/implementation-plans/2026-06-20-denix-ios-build/` (phase_01.md .. phase_05.md)
**Last updated:** 2026-06-20

## Nature of this verification: operational, not unit-test-driven

This is an **infrastructure** change. It alters *how the iOS app's toolchain is
resolved* and *how surviving Tauri/macOS patches are managed* — shell scripts
(`ios-env.sh`, `ios-postinit.sh`, `ios-check.sh`), `devenv.nix`, the `Justfile`,
`Cargo.toml`, and documentation. It does **not** change application behavior, the
Rust core logic, the frontend, or the Tauri dependency.

There are therefore **almost no unit tests**. Do **not** invent Rust unit tests
for these acceptance criteria. Verification is **operational**: a command
succeeds or fails (exit code), a `grep`/`find` returns the expected lines, a
`plutil -lint` parses, a file checksum is stable across re-runs, or a build
completes and the app runs in the iOS Simulator.

Each AC sub-item below maps to **exactly one** of two verification approaches:

- **Automated/scriptable check** — a shell command, `grep`/`find`/`plutil`
  assertion, or checksum comparison that can run unattended. Each is tagged with
  whether it runs on **[any machine]** or **[developer-machine only]** (because it
  invokes `xcrun`/`xcode-select` or compiles for iOS).
- **Human / developer-machine verification** — requires Xcode, an iOS Simulator,
  a slow `cargo tauri ios build`, or visual confirmation that the app actually
  runs. These cannot be automated here and the executor pastes command output /
  observations as evidence.

## The hard constraint: there is no CI, and iOS builds need the developer's Mac

**There is no CI in this repository** (no `.github/workflows/`, no other runner).
Every check below runs locally.

Critically, **all iOS-build verification requires the developer's macOS machine
with Xcode + an iOS Simulator installed and cannot run unattended or in any
headless/Linux environment.** This includes:

- `cargo tauri ios build --debug` / `cargo tauri ios dev` (the actual Simulator build),
- `cargo tauri ios init` (regenerates the gitignored Xcode project),
- anything that sources `ios-env.sh` and expects real, non-empty `xcrun`/`xcode-select`
  paths,
- `just ios-build` / `just ios-dev` / `just ios-postinit` / `just ios-check` against a
  real generated `project.pbxproj`.

These steps are marked **[developer-machine only]**. They are slow (`cargo tauri
ios build` compiles the Rust core + Swift glue + bundles via Xcode) and cannot be
shifted to CI. The plan's own guidance: *executors must run the build/verification
steps on the developer machine and paste output as evidence.*

A subset of checks — shell `bash -n` syntax checks, `shellcheck`, `grep` over
committed files, `just --list`, and the AC6 "no migration code" `grep`/`find`
checks — **do not** need iOS and run on **[any machine]**. Those are noted
explicitly.

---

## AC1 — No hardcoded toolchain paths; cc-wrapper conflicts resolved dynamically

**Verified in:** Phase 1 (`phase_01.md`, Tasks 1–4).

| Sub-item | Approach | Machine |
|---|---|---|
| AC1.1 | Human / developer-machine | [developer-machine only] |
| AC1.2 | Automated/scriptable | [any machine] for grep; [dev] for the delete-after-build sequencing |
| AC1.3 | Human / developer-machine (build-log assertion) | [developer-machine only] |
| AC1.4 | Human / developer-machine (build-log assertion) | [developer-machine only] |
| AC1.5 | Human / developer-machine (build-log assertion) | [developer-machine only] |
| AC1.6 | Automated/scriptable (with a manual dev-machine confirmation) | mixed |

### AC1.1 — Runnable Simulator build from the devenv shell, tools still Nix-provided
**Human / developer-machine verification.** Phase 1 Task 4 Step 1. From
`apps/identity-wallet/` inside the devenv shell:
```bash
cargo tauri ios build --debug    # or: cargo tauri ios dev
```
Must complete and produce a runnable Simulator build. **Cannot be automated in
CI:** it requires Xcode + an iOS Simulator and is a slow, GUI-toolchain build.
Tools-still-Nix-provided is confirmed by the fact that the build runs from inside
the devenv shell (node/pnpm/cargo-tauri/rustup remain Nix packages in
`devenv.nix`). Evidence = pasted build success output.

### AC1.2 — `.cargo/config.toml` deleted; overrides in `ios-env.sh`; no Xcode paths
**Automated/scriptable check.** Phase 1 Task 4 Step 2 (and Phase 1 "Done When").
```bash
grep -rn "/Applications/Xcode" apps/ devenv.nix    # [any machine] — expect: no output (exit 1)
test ! -f apps/identity-wallet/src-tauri/.cargo/config.toml && echo "deleted"  # [any machine]
```
Note the documented exception (Phase 1 Task 3 Step 2b): if `RUST_TEST_THREADS=1`
is load-bearing, a `.cargo/config.toml` containing **only** that `[env]` line may
remain — it carries no toolchain/path content, so the `/Applications/Xcode` grep
still returns nothing. The grep is the authoritative AC1.2 check and runs on any
machine. The "delete last, only after the new `ios-env.sh` path is proven by a
real Simulator build" sequencing (design plan, Reversibility) is a
**[developer-machine only]** ordering constraint on *when* the delete happens.

### AC1.3 — No `-mmacos-version-min` / `-mios-simulator-version-min` conflict
**Human / developer-machine verification.** Phase 1 Task 4 Step 1. Assert the
string `-mmacos-version-min … not allowed with -mios-simulator-version-min` does
**not** appear in the `cargo tauri ios build --debug` log. **Cannot be automated
in CI:** the error only manifests during a real iOS cross-compile, which needs
Xcode. Evidence = build log free of that clang error.

### AC1.4 — No `ld: library not found for -liconv` (host proc-macro link)
**Human / developer-machine verification.** Phase 1 Task 4 Step 1. Assert
`ld: library not found for -liconv` does **not** appear in the iOS build log.
**Cannot be automated in CI:** only surfaces during the iOS app's host-side
proc-macro link under the Nix apple-sdk stub. Evidence = build log free of that
linker error. (Guarded by construction by the `EZPDS_IOS_BUILD`-gated host
override in `ios-env.sh`; see the AC2.4 cross-phase contract.)

### AC1.5 — No `ld: framework not found UIKit` (iOS-sim final link)
**Human / developer-machine verification.** Phase 1 Task 4 Step 1. Assert
`ld: framework not found UIKit` does **not** appear in the iOS build log. **Cannot
be automated in CI:** only surfaces at the iOS-simulator final link step. Evidence
= build log free of that linker error.

### AC1.6 — Switching active Xcode requires editing no committed file
**Automated/scriptable check + manual dev-machine confirmation.** Two parts:
- The *committed* state is proven by the same AC1.2 grep — no literal Xcode path
  exists to edit, so a switch cannot require a committed-file edit
  (`grep -rn "/Applications/Xcode" apps/ devenv.nix` → empty). **[any machine]**.
- Optional full confirmation **[developer-machine only]**: run `xcode-select
  --switch` (or simulate an Xcode path change), re-source `ios-env.sh`, and confirm
  the derived vars track the new path without any file edit:
  ```bash
  ( export EZPDS_IOS_BUILD=1; source apps/identity-wallet/scripts/ios-env.sh; \
    echo "$DEVELOPER_DIR" "$CC_aarch64_apple_ios_sim" )
  ```
  Values resolve under the newly-selected Xcode. This requires `xcrun`/`xcode-select`,
  hence developer-machine only. The grep is the unattended gate; the switch test is
  the human confirmation.

---

## AC2 — Nix server build remains intact

**Verified in:** Phase 1 (`phase_01.md`, Task 4 Steps 3–4).

| Sub-item | Approach | Machine |
|---|---|---|
| AC2.1 | Automated/scriptable (command exit code) | [developer-machine only] (in devenv shell) |
| AC2.2 | Automated/scriptable (command exit code) | [developer-machine only] (in devenv shell) |
| AC2.3 | Automated/scriptable (command exit code) | [developer-machine only] (in devenv shell) |
| AC2.4 | Automated/scriptable (by-construction grep) | [developer-machine only] (in devenv shell) |

> These are scriptable (pass/fail by exit code) but still require the **devenv
> shell on the developer's Mac**, because the regression risk being guarded is
> precisely "did sourcing `ios-env.sh` in `enterShell` break the in-Nix host
> build?" — which can only be observed inside that shell on macOS. They are not
> CI-runnable here (no CI exists).

### AC2.1 — `just build` (`cargo build --workspace`) succeeds incl. host identity-wallet + security-framework
**Automated/scriptable check.** Phase 1 Task 4 Step 3, from repo root in the devenv shell:
```bash
just build    # cargo build --workspace
```
Exit 0 required. The host build of `identity-wallet` + `security-framework` must
still link. **[developer-machine only]** (devenv shell on macOS).

### AC2.2 — `just test` and `just clippy` pass in the Nix shell
**Automated/scriptable check.** Phase 1 Task 4 Step 3:
```bash
just clippy   # cargo clippy --workspace -- -D warnings
just test     # cargo test --workspace
```
Both exit 0. **[developer-machine only]** (devenv shell).

### AC2.3 — `nix build .#relay --accept-flake-config` succeeds
**Automated/scriptable check.** Phase 1 Task 4 Step 3:
```bash
nix build .#relay --accept-flake-config
```
Exit 0 / `./result/bin/relay` produced. Unaffected by `enterShell` regardless
(builds in a Nix sandbox that never sources `enterShell`), but still run on the
developer's Mac as part of this phase. **[developer-machine only]**.

### AC2.4 — Host override does not leak to the relay/server build (failure-guard)
**Automated/scriptable check (satisfied by construction).** Phase 1 Task 4 Step 4.
The host (`aarch64-apple-darwin`) overrides in `ios-env.sh` are gated behind
`EZPDS_IOS_BUILD`, which `enterShell` does **not** set. Verify in a normal dev
shell (no iOS build active):
```bash
env | grep -E 'AARCH64_APPLE_DARWIN' ; echo "darwin-overrides-exit=$?"   # expect no output, exit 1
just build && just test && cargo build -p relay                          # behave exactly as before
```
If the relay build regressed, the gated host override is **not** the cause (it is
not set here); investigate the always-on iOS-target vars (no regression expected),
and do **not** restore the deleted iOS-override config file. **[developer-machine
only]** (devenv shell).

---

## AC3 — Surviving patches automated + drift detection

**Verified in:** Phase 2 (`phase_02.md`, Tasks 1–4).

| Sub-item | Approach | Machine |
|---|---|---|
| AC3.1 | Human / developer-machine (build) + automated postinit | [developer-machine only] |
| AC3.2 | Automated/scriptable (checksum equality) | [developer-machine only] |
| AC3.3 | Automated/scriptable (exit code) | [developer-machine only] |
| AC3.4 | Automated/scriptable (exit code + message) | [developer-machine only] |
| AC3.5 | Automated/scriptable (grep both source the same file) | [developer-machine only] |

> The script *creation* and `bash -n` syntax checks (Phase 2 Tasks 1–3 Step 2)
> run on **[any machine]**. All AC3 *behavioral* checks operate on the generated,
> gitignored `project.pbxproj`, which only exists after `cargo tauri ios init` on
> the developer's Mac — hence **[developer-machine only]**.

### AC3.1 — After fresh `cargo tauri ios init`, `just ios-postinit` yields a project that `just ios-build`s
**Human / developer-machine verification (with an automated postinit step).**
Phase 2 Task 4 Steps 1, 3, 6:
```bash
cargo tauri ios init     # regenerate gitignored Xcode project [dev only]
just ios-postinit        # apply patches; expect "ios-postinit: OK" [dev only]
just ios-build           # Simulator build must complete [dev only]
```
The `ios-postinit` step is scriptable (exit code + sentinel), but the final
`just ios-build` producing a working Simulator build is the **human /
developer-machine** part — it requires Xcode + Simulator and cannot run in CI.
Evidence = pasted `ios-postinit: OK` and a successful Simulator build.

### AC3.2 — `just ios-postinit` is idempotent
**Automated/scriptable check.** Phase 2 Task 4 Step 4 — checksum equality across
two consecutive post-apply runs:
```bash
PBX=$(ls apps/identity-wallet/src-tauri/gen/apple/*.xcodeproj/project.pbxproj | head -n1)
just ios-postinit; H1=$(shasum "$PBX" | awk '{print $1}')
just ios-postinit; H2=$(shasum "$PBX" | awk '{print $1}')
[ "$H1" = "$H2" ] && echo IDEMPOTENT || echo "NOT IDEMPOTENT"
```
Expect `IDEMPOTENT` and the `sentinel present` no-op message both runs.
**[developer-machine only]** (needs the generated pbxproj).

### AC3.3 — `just ios-check` exits 0 when all three patches present
**Automated/scriptable check.** Phase 2 Task 4 Step 5:
```bash
just ios-check; echo "exit=$?"    # expect: "ios-check: OK — all patches present", exit=0
```
**[developer-machine only]** (needs the patched pbxproj).

### AC3.4 — `just ios-check` exits non-zero and names the missing patch when any is absent
**Automated/scriptable check.** Phase 2 Task 4 Step 2 — run *before* `ios-postinit`
on a freshly generated project:
```bash
just ios-check; echo "exit=$?"    # expect >=1 "ios-check: FAIL — …" line and exit=1
```
The fresh project has `ENABLE_USER_SCRIPT_SANDBOXING = YES` and no
`ezpds-ios-env` sentinel, so the check names those gaps. **[developer-machine
only]** (needs an unpatched generated pbxproj).

### AC3.5 — Run Script phase and CLI build resolve the toolchain identically (one source of truth)
**Automated/scriptable check.** Phase 2 Task 4 Step 6 — confirm the injected Run
Script block references the *same* `ios-env.sh` that `devenv.nix` sources:
```bash
grep -n 'ezpds-ios-env' "$PBX"
grep -n 'scripts/ios-env.sh' "$PBX"
```
Both must reference `apps/identity-wallet/scripts/ios-env.sh` — identical to the
path sourced in `devenv.nix`'s `enterShell` (cross-checkable with
`grep -n 'ios-env.sh' devenv.nix`, which is **[any machine]**). The pbxproj greps
are **[developer-machine only]** (need the patched generated file).

---

## AC4 — Documentation reflects the de-Nixed workflow

**Verified in:** Phase 3 (`phase_03.md`, Tasks 1–3).

| Sub-item | Approach | Machine |
|---|---|---|
| AC4.1 | Automated/scriptable (grep) | [any machine] |
| AC4.2 | Automated/scriptable (grep) | [any machine] |
| AC4.3 | Automated/scriptable (grep date) | [any machine] |

> All AC4 checks operate on committed Markdown and run on **[any machine]** — no
> Xcode needed. A light human read confirms the prose is coherent, but the
> pass/fail gates are greps.

### AC4.1 — `apps/identity-wallet/AGENTS.md` documents `ios-env.sh` and the `just ios-*` workflow
**Automated/scriptable check.** Phase 3 "Done When":
```bash
grep -nE "ios-env\.sh|just ios-(postinit|check|dev|build)" apps/identity-wallet/AGENTS.md
```
Expect hits for `ios-env.sh` and the `just ios-*` recipes. **[any machine]**.

### AC4.2 — No doc instructs editing `.cargo/config.toml` or hardcoding an Xcode path; obsolete cc-wrapper entries removed/relabeled
**Automated/scriptable check.** Phase 3 Task 2 Step 3:
```bash
grep -n "/Applications/Xcode" apps/identity-wallet/AGENTS.md
grep -n "\.cargo/config.toml" apps/identity-wallet/AGENTS.md
grep -niE "sed -i|ENABLE_USER_SCRIPT_SANDBOXING = YES" apps/identity-wallet/AGENTS.md
```
Expect no output except, at most, a clearly-labeled historical "(resolved)" note —
no instruction tells the reader to perform these manually. **[any machine]**.

### AC4.3 — "Last verified"/"Last updated" dates bumped on every edited AGENTS.md
**Automated/scriptable check.** Phase 3 Task 3 Step 2:
```bash
grep -nE "Last (verified|updated): 2026-06-20" apps/identity-wallet/AGENTS.md
grep -nE "Last verified: 2026-06-20" AGENTS.md
```
Both edited AGENTS.md files carry `2026-06-20`. **[any machine]**.

---

## AC5 — Upstream bugs documented locally (for later manual filing)

**Verified in:** Phase 4 (`phase_04.md`, Tasks 1–2).

| Sub-item | Approach | Machine |
|---|---|---|
| AC5.1 | Automated/scriptable (grep) + human read of reproductions | [any machine] |
| AC5.2 | Automated/scriptable (grep across 4 files) | [any machine] |

> Documentation only — all checks run on **[any machine]**. No upstream issue is
> filed in this plan (explicitly a manual follow-up).

### AC5.1 — Local record documents both bugs with a minimal reproduction + exact workaround
**Automated/scriptable check (+ human read).** Phase 4 Task 1 Step 2:
```bash
grep -c '^## Bug' docs/ios-upstream-bugs.md    # expect: 2
```
Both bugs (swift-rs `sandbox_apply` EPERM on macOS 26; Xcode user-script-sandbox
blocking Cargo) must be present, each with a Reproduction and Workaround section. A
short human read confirms the reproductions are concrete (the `grep -c` proves both
sections exist). **[any machine]**.

### AC5.2 — Patch comment, `ios-postinit` script, and `AGENTS.md` reference the record with "remove when fixed upstream"
**Automated/scriptable check.** Phase 4 Task 2 Step 3:
```bash
grep -rn "ios-upstream-bugs.md" \
  apps/identity-wallet/swift-rs-patch/src-rs/build.rs \
  Cargo.toml \
  apps/identity-wallet/scripts/ios-postinit.sh \
  apps/identity-wallet/AGENTS.md
```
Expect at least one hit in each of the four files; the swift-rs/Cargo references
carry a "remove when fixed upstream" note. **[any machine]**.

---

## AC6 — Migration decision record (documentation only)

**Verified in:** Phase 5 (`phase_05.md`, Tasks 1–2).

| Sub-item | Approach | Machine |
|---|---|---|
| AC6.1 | Automated/scriptable (grep) + human read | [any machine] |
| AC6.2 | Automated/scriptable (negative grep/find) | [any machine] |

> Documentation + a negative ("nothing was added") check — both run on
> **[any machine]**, no Xcode required.

### AC6.1 — Decision record states the migration, its trigger, and "port the shell, never the crypto"
**Automated/scriptable check (+ human read).** Phase 5 Task 1 Step 2:
```bash
grep -niE "BGTaskScheduler|port the (ui )?shell|never|UniFFI" docs/mobile-native-migration-decision.md
```
Expect matches for the trigger (background PLC monitoring → `BGTaskScheduler`), the
"never reimplement the crypto in Swift" rule, and UniFFI. Also confirm the pointer
from `apps/identity-wallet/AGENTS.md` exists. A human read confirms the record reads
as a coherent decision. **[any machine]**.

### AC6.2 — No SwiftUI/UniFFI/FFI code added; Tauri dependency and app behavior unchanged (negative)
**Automated/scriptable check.** Phase 5 Task 2 Step 1:
```bash
grep -rniE "uniffi|swift-bridge|swift_bridge" --include=Cargo.toml . ; echo "deps-exit=$?"   # expect no matches, deps-exit=1
find apps/identity-wallet -name '*.swift' -not -path '*/swift-rs-patch/*' -not -path '*/gen/*'  # expect: no output
grep -n '^tauri ' apps/identity-wallet/src-tauri/Cargo.toml                                    # expect: existing tauri dep present
```
No UniFFI/swift-bridge dep added, no new app-level `.swift` source, Tauri still a
dependency. **[any machine]**.

---

## Summary table — every AC sub-item mapped (no gaps)

| AC | Approach | Machine | Source |
|---|---|---|---|
| AC1.1 | Human / developer-machine (Simulator build) | dev only | phase_01 T4 S1 |
| AC1.2 | Automated (`grep`/file-absent) | any (grep) | phase_01 T4 S2 |
| AC1.3 | Human / developer-machine (build-log assertion) | dev only | phase_01 T4 S1 |
| AC1.4 | Human / developer-machine (build-log assertion) | dev only | phase_01 T4 S1 |
| AC1.5 | Human / developer-machine (build-log assertion) | dev only | phase_01 T4 S1 |
| AC1.6 | Automated (`grep`) + dev-machine switch confirmation | mixed | phase_01 T4 S2 / T1 S3 |
| AC2.1 | Automated (`just build` exit code) | dev only (devenv shell) | phase_01 T4 S3 |
| AC2.2 | Automated (`just test`/`just clippy` exit code) | dev only (devenv shell) | phase_01 T4 S3 |
| AC2.3 | Automated (`nix build .#relay` exit code) | dev only (devenv shell) | phase_01 T4 S3 |
| AC2.4 | Automated (by-construction env grep) | dev only (devenv shell) | phase_01 T4 S4 |
| AC3.1 | Human / developer-machine (Simulator build) + automated postinit | dev only | phase_02 T4 S1,3,6 |
| AC3.2 | Automated (checksum equality) | dev only | phase_02 T4 S4 |
| AC3.3 | Automated (`just ios-check` exit 0) | dev only | phase_02 T4 S5 |
| AC3.4 | Automated (`just ios-check` exit !=0 + message) | dev only | phase_02 T4 S2 |
| AC3.5 | Automated (`grep` both source same file) | dev only (pbxproj) | phase_02 T4 S6 |
| AC4.1 | Automated (`grep`) | any | phase_03 Done-When |
| AC4.2 | Automated (`grep`) | any | phase_03 T2 S3 |
| AC4.3 | Automated (`grep` date) | any | phase_03 T3 S2 |
| AC5.1 | Automated (`grep -c`) + human read | any | phase_04 T1 S2 |
| AC5.2 | Automated (`grep` across 4 files) | any | phase_04 T2 S3 |
| AC6.1 | Automated (`grep`) + human read | any | phase_05 T1 S2 |
| AC6.2 | Automated (negative `grep`/`find`) | any | phase_05 T2 S1 |

**Coverage:** All 22 sub-items (AC1.1–AC6.2) map to exactly one approach. Nothing
is left unmapped.

## Pre-flight checks runnable on any machine (no Xcode)

Useful as a fast first gate before the developer-machine pass:
- `bash -n` on `ios-env.sh`, `ios-postinit.sh`, `ios-check.sh` (and `shellcheck` if present).
- `just --list` shows `ios-postinit`, `ios-check`, `ios-dev`, `ios-build`.
- All AC1.2, AC4.*, AC5.*, AC6.* greps/finds above.

## What must happen on the developer's Mac (cannot be automated here)

- AC1.1, AC1.3, AC1.4, AC1.5 — the actual `cargo tauri ios build --debug` Simulator
  build and its log assertions.
- AC1.6 (optional `xcode-select --switch` confirmation), and all `ios-env.sh`
  source-and-echo checks that need real `xcrun`/`xcode-select` paths.
- AC2.1–AC2.4 — the in-devenv-shell `just build`/`test`/`clippy`, `nix build
  .#relay`, and the env-leak guard.
- AC3.1–AC3.5 — everything operating on the generated, gitignored `project.pbxproj`
  (after `cargo tauri ios init`), including the `just ios-build` Simulator build.

The executor runs these on macOS + Xcode + Simulator and pastes command output (and,
for the Simulator builds, confirmation the app launches) as evidence.
