# Human Test Plan: De-Nix iOS Build

Feature: `docs/implementation-plans/2026-06-20-denix-ios-build/`
Generated: 2026-06-21

All steps below run on the **developer's macOS machine** with Xcode + an iOS Simulator installed, inside the devenv shell (entered from the **workspace root**). These are the checks that cannot be automated in a headless environment.

## Prerequisites

- macOS with **Xcode** (opened once to accept license) + an **iOS Simulator** platform installed; **CocoaPods** installed.
- Dev shell active, from the workspace root:
  ```bash
  nix develop --impure --accept-flake-config
  ```
- Confirm `echo $DEVELOPER_DIR` shows a **real Xcode path** (e.g. `/Applications/Xcode.app/Contents/Developer`), not a Nix store path — proves `enterShell` sourced `ios-env.sh`.

---

## Phase 1 — Toolchain resolves dynamically; iOS build runs (AC1.1, AC1.3–AC1.5, AC1.6)

| Step | Action | Expected |
|------|--------|----------|
| 1 | `cd apps/identity-wallet && cargo tauri ios build --debug` (or `cargo tauri ios dev`). Capture the full log. | Build completes; produces a runnable Simulator build. **(AC1.1)** |
| 2 | In that same log, search for `-mmacos-version-min … not allowed with -mios-simulator-version-min`. | **Absent.** **(AC1.3)** |
| 3 | Search the log for `ld: library not found for -liconv`. | **Absent** (host proc-macro link resolves under the `EZPDS_IOS_BUILD`-gated host override). **(AC1.4)** |
| 4 | Search the log for `ld: framework not found UIKit`. | **Absent** (iOS-sim final link). **(AC1.5)** |
| 5 | `( export EZPDS_IOS_BUILD=1; source apps/identity-wallet/scripts/ios-env.sh; echo "$DEVELOPER_DIR" "$CC_aarch64_apple_ios_sim" )` | Both resolve to paths under the active Xcode, with **no committed file edited**. Optionally `xcode-select --switch` to another Xcode, re-source, confirm values track the new path. **(AC1.6 confirmation)** |

---

## Phase 2 — Nix server build intact under the new `enterShell` (AC2.1–AC2.4)

| Step | Action | Expected |
|------|--------|----------|
| 1 | From repo root: `just build` | Exit 0 — `cargo build --workspace` links host `identity-wallet` + `security-framework`. **(AC2.1)** |
| 2 | `just clippy` then `just test` | Both exit 0. **(AC2.2)** |
| 3 | `nix build .#relay --accept-flake-config` | Exit 0; `./result/bin/relay` produced. **(AC2.3)** |
| 4 | In a normal dev shell (no iOS build active): `env | grep -E 'AARCH64_APPLE_DARWIN'; echo "exit=$?"` | **No output, exit 1** — host overrides are gated behind `EZPDS_IOS_BUILD`, which `enterShell` does not set. **(AC2.4)** |

---

## Phase 3 — Surviving patches automated + drift detection (AC3.1–AC3.5)

Operates on the **generated, gitignored** `project.pbxproj`. Run from repo root.

| Step | Action | Expected |
|------|--------|----------|
| 1 | `cargo tauri ios init` (regenerates the Xcode project) | Fresh project created under `apps/identity-wallet/src-tauri/gen/apple/`. |
| 2 | **Before** patching: `just ios-check; echo "exit=$?"` | Exit **1**, with `ios-check: FAIL — …` lines naming the unpatched gaps. **(AC3.4)** |
| 3 | `just ios-postinit` | Prints `ios-postinit: OK`. **(AC3.1, apply step)** |
| 4 | Idempotency: <br>`PBX=$(ls apps/identity-wallet/src-tauri/gen/apple/*.xcodeproj/project.pbxproj \| head -n1)`<br>`just ios-postinit; H1=$(shasum "$PBX" \| awk '{print $1}')`<br>`just ios-postinit; H2=$(shasum "$PBX" \| awk '{print $1}')`<br>`[ "$H1" = "$H2" ] && echo IDEMPOTENT \|\| echo "NOT IDEMPOTENT"` | `IDEMPOTENT`; both runs print the sentinel-present no-op message. **(AC3.2)** |
| 5 | `just ios-check; echo "exit=$?"` | `ios-check: OK — all patches present`, exit **0**. **(AC3.3)** |
| 6 | `grep -n 'ezpds-ios-env' "$PBX"` and `grep -n 'scripts/ios-env.sh' "$PBX"` | Both reference `apps/identity-wallet/scripts/ios-env.sh` — identical to the path in `devenv.nix`. Single source of truth confirmed. **(AC3.5)** |
| 7 | `just ios-build` (or `just ios-dev`) on the patched project | Simulator build completes; app launches. **(AC3.1, end-to-end)** |

---

## End-to-End: Fresh-clone developer onboarding

**Purpose:** Validates the headline outcome — a new developer reaches a running iOS app with no manual file edits and no hardcoded paths, and the existing server workflow is untouched.

1. From a clean checkout: enter the dev shell from the workspace root; confirm `$DEVELOPER_DIR` is the real Xcode.
2. `cd apps/identity-wallet && pnpm install`
3. `cargo tauri ios init` → `just ios-postinit` (expect `ios-postinit: OK`) → `just ios-check` (expect exit 0)
4. `just ios-dev` → the app builds and launches in the Simulator; the onboarding screen renders.
5. Back at repo root: `just build && just test` both pass — confirming the iOS toolchain wiring did not regress the host/server build.

**Result:** running app in Simulator + green `just build`/`just test`, with no committed file edited to make iOS resolve the toolchain.

---

## Traceability — full AC coverage

| AC | Automated (CI-safe, already verified) | Manual (developer machine) |
|----|---------------------------------------|---------------------------|
| AC1.1 | — | Phase 1 §1 |
| AC1.2 | Xcode-path grep + config.toml content — PASS | — |
| AC1.3 | — | Phase 1 §2 |
| AC1.4 | — | Phase 1 §3 |
| AC1.5 | — | Phase 1 §4 |
| AC1.6 | Xcode-path grep (committed state) — PASS | Phase 1 §5 |
| AC2.1 | — | Phase 2 §1 |
| AC2.2 | — | Phase 2 §2 |
| AC2.3 | — | Phase 2 §3 |
| AC2.4 | `devenv.nix` does not set `EZPDS_IOS_BUILD` (verified) — PASS | Phase 2 §4 |
| AC3.1 | — | Phase 3 §3, §7 |
| AC3.2 | sentinel/plutil logic in ios-postinit.sh — verified | Phase 3 §4 |
| AC3.3 | ios-check.sh sentinel grep — verified | Phase 3 §5 |
| AC3.4 | ios-check.sh failure paths — verified | Phase 3 §2 |
| AC3.5 | ios-postinit path == devenv.nix path — PASS | Phase 3 §6 |
| AC4.1 | AGENTS.md grep — PASS | — |
| AC4.2 | Three negative greps — PASS | — |
| AC4.3 | Dates bumped to 2026-06-21 (newer than 2026-03-31 baseline) — PASS | — |
| AC5.1 | `grep -c '^## Bug'` → 2 — PASS | Read reproductions in docs/ios-upstream-bugs.md |
| AC5.2 | 4-file reference grep — PASS | — |
| AC6.1 | Decision-record grep + AGENTS.md pointer — PASS | Read docs/mobile-native-migration-decision.md for coherence |
| AC6.2 | Negative dep/.swift grep + tauri present — PASS | — |
