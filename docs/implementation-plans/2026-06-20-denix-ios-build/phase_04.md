# De-Nix the iOS Build — Phase 4: Local upstream-bug documentation

**Goal:** Document the two surviving macOS/Xcode bugs (with reproductions + the exact workaround) in one local record so they can be filed/PR'd upstream manually later, and link that record from the code/docs with a "remove when fixed upstream" note.

**Architecture:** One new doc + a few comment links. No behavior change. (Per AC5, this phase does **not** file anything upstream — that is a manual follow-up the user does on their own schedule.)

**Tech Stack:** Markdown.

**Scope:** Phase 4 of 5 from `docs/design-plans/2026-06-20-denix-ios-build.md`.

**Codebase verified:** 2026-06-20.

> **Verified anchors:**
> - swift-rs patch: `apps/identity-wallet/swift-rs-patch/src-rs/build.rs:262-264` (the `--disable-sandbox` arg + macOS-26 comment).
> - Root `Cargo.toml` ([patch.crates-io] block + comment, ~L94-102). Locate by text — the `# Remove when swift-rs ships a fix upstream.` line is ~L99 and `[patch.crates-io]` is ~L100; do not trust the exact number.
> - `docs/` has no ADR/decisions dir; flat notes live at `docs/*.md`. Place the record at `docs/ios-upstream-bugs.md`.

---

## Acceptance Criteria Coverage

### denix-ios-build.AC5: Upstream bugs documented locally (for later manual filing)
- **denix-ios-build.AC5.1 Success:** A local record documents both bugs — swift-rs `sandbox_apply` EPERM on macOS 26, and Xcode user-script-sandbox blocking Cargo — each with a minimal reproduction and the exact workaround applied.
- **denix-ios-build.AC5.2 Success:** The swift-rs patch comment, the `ios-postinit` script, and `CLAUDE.md` reference this local record with a "remove when fixed upstream" note.

**Verifies (this phase):** denix-ios-build.AC5.1, AC5.2. Documentation — verified by read/grep.

---

<!-- START_TASK_1 -->
### Task 1: Create `docs/ios-upstream-bugs.md`

**Files:**
- Create: `docs/ios-upstream-bugs.md`

**Step 1: Create the file** with this content (fill the two `Reproduction` blocks with the exact error text observed during Phase 1-2 verification if it differs):

```markdown
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
```

**Step 2: Verify it renders / has both sections**
```bash
grep -c '^## Bug' docs/ios-upstream-bugs.md
```
Expected: `2`.

**Step 3: Commit**
```bash
git add docs/ios-upstream-bugs.md
git commit -m "docs: record iOS upstream bugs (swift-rs sandbox, Xcode user-script sandbox)"
```
<!-- END_TASK_1 -->

<!-- START_TASK_2 -->
### Task 2: Link the record from the code with "remove when fixed upstream" notes

**Files:**
- Modify: `apps/identity-wallet/swift-rs-patch/src-rs/build.rs:262-264` (extend the existing comment)
- Modify: `Cargo.toml:95-100` (extend the existing `[patch.crates-io]` comment)

**Step 1: `swift-rs-patch/src-rs/build.rs`** — extend the comment above `.arg("--disable-sandbox")` (currently L262-263) to:
```rust
            // On macOS 26 (Tahoe), sandbox_apply() returns EPERM when SPM tries to
            // sandbox manifest compilation. Disable the sandbox to allow the build.
            // See docs/ios-upstream-bugs.md (Bug 1). Remove this fork when fixed upstream.
```

**Step 2: Root `Cargo.toml`** — locate the comment line `# Remove when swift-rs ships a fix upstream.` (just above `[patch.crates-io]`, ~L99) and replace that single line with:
```toml
# Remove when swift-rs ships a fix upstream. Tracked in docs/ios-upstream-bugs.md (Bug 1).
```

(The `ios-postinit.sh` header comment created in Phase 2 already references `docs/ios-upstream-bugs.md`, and the `CLAUDE.md` swift-rs troubleshooting entry was repointed in Phase 3. Confirm both in Step 3.)

**Step 3: Verify all references exist**
```bash
grep -rn "ios-upstream-bugs.md" \
  apps/identity-wallet/swift-rs-patch/src-rs/build.rs \
  Cargo.toml \
  apps/identity-wallet/scripts/ios-postinit.sh \
  apps/identity-wallet/CLAUDE.md
```
Expected: at least one hit in each of the four files.

**Step 4: Commit**
```bash
git add apps/identity-wallet/swift-rs-patch/src-rs/build.rs Cargo.toml
git commit -m "docs: link ios-upstream-bugs.md from swift-rs patch and Cargo.toml"
```
<!-- END_TASK_2 -->

---

## Phase 4 Done When

- `docs/ios-upstream-bugs.md` exists with both bugs, each carrying a reproduction + the exact workaround (AC5.1).
- The swift-rs patch comment, `Cargo.toml`, `ios-postinit.sh`, and `CLAUDE.md` all reference the record with a "remove when fixed upstream" note (AC5.2) — verified by the Task 2 grep.
- Edits committed. (No upstream issue is filed in this phase — that is a manual follow-up.)
