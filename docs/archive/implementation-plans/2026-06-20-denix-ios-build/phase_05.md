# De-Nix the iOS Build — Phase 5: Native SwiftUI migration decision record (documentation only)

**Goal:** Record the validated "destination" architecture (native SwiftUI shell over the same Rust core) and its concrete trigger, so the decision is captured and discoverable — without building any of it.

**Architecture:** One new decision-record doc + a AGENTS.md pointer. **No FFI, no SwiftUI, no Tauri changes.**

**Tech Stack:** Markdown.

**Scope:** Phase 5 of 5 from `docs/design-plans/2026-06-20-denix-ios-build.md`.

**Codebase verified:** 2026-06-20.

> **Verified facts to cite in the record:**
> - In `apps/identity-wallet/src-tauri/src/plc_monitor.rs`, only `run_monitoring_loop` (L225) and `emit_if_alerts` (L249) — plus the `check_identity_status` IPC command (L260-261) — touch Tauri (`tauri::AppHandle`, `Emitter`, `app_handle.emit`). The core `check_all` (L58) and `check_for_changes` (L89) are framework-agnostic (no Tauri references).
> - `docs/` keeps flat spec/decision notes at `docs/*.md`; there is no ADR directory.

---

## Acceptance Criteria Coverage

### denix-ios-build.AC6: Migration decision record (documentation only)
- **denix-ios-build.AC6.1 Success:** A decision record states the SwiftUI-shell-over-Rust-core migration, its trigger (background PLC monitoring becomes a hard requirement), and "port the shell, never the crypto."
- **denix-ios-build.AC6.2 Success (negative):** No SwiftUI/UniFFI/FFI code is added by this plan; the Tauri dependency and app behavior are unchanged.

**Verifies (this phase):** denix-ios-build.AC6.1, AC6.2. Documentation — AC6.2 is verified by confirming the absence of migration code.

---

<!-- START_TASK_1 -->
### Task 1: Create `docs/mobile-native-migration-decision.md`

**Files:**
- Create: `docs/mobile-native-migration-decision.md`

**Step 1: Create the file** with this content:

```markdown
# Decision record: native SwiftUI shell over the Rust core (DEFERRED)

Status: **Deferred — not scheduled.** Recorded 2026-06-20.

## Decision

If/when we leave Tauri for the iOS app, migrate to a **native SwiftUI shell over
the existing Rust core** (Rust exposed to Swift via UniFFI), NOT a full Swift
rewrite. Port the UI shell; never reimplement the crypto core in Swift.

## Trigger (the one signal that justifies starting)

**Background PLC monitoring becomes a hard requirement.** Today
`apps/identity-wallet/src-tauri/src/plc_monitor.rs` runs a foreground
`tokio::time::interval` (`run_monitoring_loop`, L225) that iOS suspends when the
app is backgrounded. True periodic checks against the 72h recovery window need
Apple's `BGTaskScheduler` / `BGAppRefreshTask`, reachable only from native Swift.
Note: even staying on Tauri, background tasks require a custom Swift plugin — so
the real migration signal is "we need background execution," not "the build annoys
me." (The build friction is addressed by the de-Nix work; see
docs/design-plans/2026-06-20-denix-ios-build.md.)

Secondary triggers: a Tauri iOS bug blocks *this app* specifically (e.g. a
WKWebView rendering defect we can't work around), or Android becomes a real
requirement (then reconsider Flutter/KMP vs SwiftUI).

## Why this shape (from the 2026 re-evaluation)

- The Rust core is the asset (did:plc genesis/rotation/recovery, P-256 + Secure
  Enclave, DAG-CBOR, Shamir). Reimplementing it in Swift is the highest-risk,
  highest-cost option and is explicitly ruled out.
- A SwiftUI shell deletes the remaining Tauri-specific glue (swift-rs patch, Run
  Script patches) and unlocks `BGTaskScheduler`, while the Rust core ports
  unchanged via UniFFI.
- Keep Secure Enclave/Keychain in Rust; use Swift only for LAContext/biometric UI.

## Why it's pre-de-risked (low switching cost when the trigger fires)

The monitoring logic is already cleanly separated: only `run_monitoring_loop`
(L225) and `emit_if_alerts` (L249) in `plc_monitor.rs` touch Tauri; `check_all`
(L58) and `check_for_changes` (L89) are framework-agnostic and port as-is behind a
`BGAppRefreshTask` handler. The rest of the Rust backend (device_key, keychain,
oauth_client, pds_client, claim, recovery) has no Tauri coupling in its core logic.

## Explicitly out of scope now

No SwiftUI project, no UniFFI bindings, no FFI layer, no removal of Tauri. This is
a decision record only. Revisit when the trigger above is met.
```

**Step 2: Verify it captures the trigger and the "port the shell, never the crypto" rule**
```bash
grep -niE "BGTaskScheduler|port the (ui )?shell|never|UniFFI" docs/mobile-native-migration-decision.md
```
Expected: matches for the trigger (BGTaskScheduler), the "never reimplement … in Swift" rule, and UniFFI.

**Step 3: Add a pointer from `apps/identity-wallet/AGENTS.md`** — under the existing "Key Decisions" section, add:
```markdown
- **Native migration is deferred, trigger-gated**: see `docs/mobile-native-migration-decision.md`. Migrate to a SwiftUI shell over the Rust core (UniFFI) only when background PLC monitoring becomes a hard requirement; port the shell, never the crypto.
```

**Step 4: Commit**
```bash
git add docs/mobile-native-migration-decision.md apps/identity-wallet/AGENTS.md
git commit -m "docs: record deferred native SwiftUI migration decision + trigger"
```
<!-- END_TASK_1 -->

<!-- START_TASK_2 -->
### Task 2: Verify no migration code was introduced (AC6.2 negative)

**Files:** none (verification only).

**Step 1: Confirm no SwiftUI/UniFFI/FFI code or deps were added across the whole plan**
```bash
# No UniFFI / swift-bridge dependency anywhere:
grep -rniE "uniffi|swift-bridge|swift_bridge" --include=Cargo.toml . ; echo "deps-exit=$?"
# No new .swift app source (the only Swift is the pre-existing swift-rs-patch vendored crate):
find apps/identity-wallet -name '*.swift' -not -path '*/swift-rs-patch/*' -not -path '*/gen/*'
# Tauri still a dependency (unchanged):
grep -n '^tauri ' apps/identity-wallet/src-tauri/Cargo.toml
```
Expected:
- First grep: `deps-exit=1` (no matches — no UniFFI/swift-bridge added).
- `find`: no output (no new app-level Swift files).
- Last grep: the existing `tauri = { version = "2", ... }` line is present (dependency unchanged).

**Step 2: No commit** (verification only).
<!-- END_TASK_2 -->

---

## Phase 5 Done When

- `docs/mobile-native-migration-decision.md` exists, stating the SwiftUI-shell-over-Rust-core decision, the background-monitoring trigger, and "port the shell, never the crypto" (AC6.1), and is linked from `apps/identity-wallet/AGENTS.md`.
- The Task 2 checks confirm no SwiftUI/UniFFI/FFI code or deps were added and Tauri is unchanged (AC6.2).
- Edits committed.
