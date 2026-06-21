# De-Nix the iOS Build — Phase 3: Documentation overhaul

**Goal:** Update `apps/identity-wallet/CLAUDE.md` and the root `CLAUDE.md` so a fresh-machine setup follows `ios-env.sh` + the `just ios-*` recipes, and remove/retire the obsolete manual-patch and cc-wrapper instructions.

**Architecture:** Documentation-only edits. No code.

**Tech Stack:** Markdown.

**Scope:** Phase 3 of 5 from `docs/design-plans/2026-06-20-denix-ios-build.md`.

**Codebase verified:** 2026-06-20.

> **Depends on:** Phases 1-2 (the final shapes of `ios-env.sh`, `ios-postinit.sh`, `ios-check.sh`, and the `just` recipes). Write this phase after those exist so the docs describe what's actually there.

> **Verified line anchors (apps/identity-wallet/CLAUDE.md):**
> - L3 `Last verified: 2026-03-31`, L4 `Last updated: 2026-03-31`
> - L157 `## First-Time Setup`
> - L177 `### Xcode build phase PATH (one-time manual step after \`cargo tauri ios init\`)`
> - L191 `### Disable user script sandboxing (one-time manual step after \`cargo tauri ios init\`)`
> - L208 `### Why rustup instead of Nix-managed Rust`
> - L212 `## Development Workflow`
> - Troubleshooting subsections: L350 Connection refused; L358 can't find crate core; L368 simctl not found / DEVELOPER_DIR; L378 `-mmacos-version-min`; L386 `-liconv`; L394 `framework not found UIKit`; L402 swift-rs `sandbox_apply`; L410 `cargo: command not found`; L418 user-script sandbox.
>
> **Verified line anchors (root CLAUDE.md):** L3 `Last verified: 2026-03-31`; L27 shell-provides list; L42 `## Mobile`, L44-45 mobile bullets.
>
> **Locating method:** line numbers are correct as of 2026-06-20 (Phases 1-2 don't touch these docs), but **locate each section by its heading TEXT, not the raw line number** — grep for the `### `/`## ` heading and edit there. Line numbers are a hint; the heading is the durable anchor.

---

## Acceptance Criteria Coverage

### denix-ios-build.AC4: Documentation reflects the de-Nixed workflow
- **denix-ios-build.AC4.1 Success:** `apps/identity-wallet/CLAUDE.md` documents `ios-env.sh` and the `just ios-*` workflow.
- **denix-ios-build.AC4.2 Success:** No doc instructs editing `.cargo/config.toml` or hardcoding an Xcode path; obsolete cc-wrapper troubleshooting entries are removed or marked historical.
- **denix-ios-build.AC4.3 Success:** "Last verified"/"Last updated" dates are bumped on every edited CLAUDE.md.

**Verifies (this phase):** denix-ios-build.AC4.1, AC4.2, AC4.3. Documentation — verified by grep/read, no tests.

---

<!-- START_TASK_1 -->
### Task 1: Rewrite the iOS setup sections of `apps/identity-wallet/CLAUDE.md`

**Files:**
- Modify: `apps/identity-wallet/CLAUDE.md` (First-Time Setup region, L157-L210)

**Step 1: Replace the two "one-time manual step" subsections (L177-L206) with one `just ios-postinit` step.**

Delete the entire `### Xcode build phase PATH …` (L177) and `### Disable user script sandboxing …` (L191) subsections and replace both with:

```markdown
### After every `cargo tauri ios init`: run `just ios-postinit`

`cargo tauri ios init` regenerates the gitignored Xcode project at
`src-tauri/gen/apple/`. Three workarounds must be (re-)applied to it. This is now
a single idempotent command, run from the repo root:

```bash
just ios-postinit
```

It (1) verifies the `swift-rs` `--disable-sandbox` patch is wired in the workspace
`Cargo.toml`, (2) sets `ENABLE_USER_SCRIPT_SANDBOXING = NO` (macOS 26 + Xcode
sandbox blocks Cargo's directory walk), and (3) injects `PATH` + `source
scripts/ios-env.sh` into the "Build Rust Code" Run Script phase (that phase does
not inherit the dev-shell environment). Verify at any time with `just ios-check`.
```

**Step 2: Update the `### Why rustup instead of Nix-managed Rust` subsection (L208)** — it remains accurate (rustup stays). Append a sentence:

```markdown

The Apple toolchain (clang/ar/SDKs/`DEVELOPER_DIR`) is resolved dynamically by
`scripts/ios-env.sh` via `xcrun`/`xcode-select` — there are no hardcoded Xcode
paths, so the build follows whatever Xcode `xcode-select` points at. `ios-env.sh`
is sourced by the devenv `enterShell` and by the patched Xcode Run Script phase.
```

**Step 3: Update the First-Time Setup intro (around L157-L175)** so the numbered setup ends with: enter the dev shell (Nix still provides node/pnpm/cargo-tauri/rustup), `pnpm install`, `cargo tauri ios init`, then `just ios-postinit`. Remove any instruction to hand-edit `project.pbxproj` or `.cargo/config.toml`.

**Step 4: Commit**
```bash
git add apps/identity-wallet/CLAUDE.md
git commit -m "docs(identity-wallet): document ios-env.sh + just ios-postinit setup"
```
<!-- END_TASK_1 -->

<!-- START_TASK_2 -->
### Task 2: Update Development Workflow + retire obsolete Troubleshooting entries in `apps/identity-wallet/CLAUDE.md`

**Files:**
- Modify: `apps/identity-wallet/CLAUDE.md` (Development Workflow L212+; Troubleshooting L348-L427)

**Step 1: Development Workflow (L212)** — present `just ios-dev` / `just ios-build` (run from repo root) as the primary commands; keep the existing "Do not click Run in Xcode" guidance.

**Step 2: Troubleshooting — remove or relabel the now-resolved entries:**

- **Delete** (now structurally prevented by `ios-env.sh`): L378 `-mmacos-version-min`, L386 `-liconv`, L394 `framework not found UIKit`.
- **Delete** (now applied by `just ios-postinit`): L410 `cargo: command not found`. Replace the **L368** `simctl not found / DEVELOPER_DIR` and **L418** user-script-sandbox entries' "Fix" text to point at `just ios-postinit` / `ios-env.sh` rather than manual `export`/`sed`.
- **Keep** L402 swift-rs `sandbox_apply` but reframe the fix as "applied automatically; see `docs/ios-upstream-bugs.md`" (created in Phase 4).
- **Keep** L350 Connection refused and L358 can't-find-crate (still relevant). For L358, the fix already references rustup — leave as-is.

**Step 3: Confirm no stale references remain**
```bash
grep -n "/Applications/Xcode" apps/identity-wallet/CLAUDE.md
grep -n "\.cargo/config.toml" apps/identity-wallet/CLAUDE.md
grep -niE "sed -i|ENABLE_USER_SCRIPT_SANDBOXING = YES" apps/identity-wallet/CLAUDE.md
```
Expected: no output except, at most, a historical mention inside a clearly-labeled "(resolved)" note. No instruction tells the reader to perform these manually.

**Step 4: Commit**
```bash
git add apps/identity-wallet/CLAUDE.md
git commit -m "docs(identity-wallet): retire obsolete cc-wrapper/manual-patch troubleshooting"
```
<!-- END_TASK_2 -->

<!-- START_TASK_3 -->
### Task 3: Update root `CLAUDE.md` mobile pointer and bump freshness dates

**Files:**
- Modify: `CLAUDE.md` (root; L42-L45 Mobile section, L3 date)
- Modify: `apps/identity-wallet/CLAUDE.md` (L3-L4 dates)

**Step 1: Root `CLAUDE.md` Mobile section (L42)** — add a bullet:
```markdown
- iOS build commands: `just ios-dev` / `just ios-build` (run from repo root; macOS + Xcode required). Toolchain resolved by `apps/identity-wallet/scripts/ios-env.sh`; patches re-applied via `just ios-postinit` after `cargo tauri ios init`.
```

**Step 2: Bump dates.**
- `apps/identity-wallet/CLAUDE.md` L3-L4: set both `Last verified:` and `Last updated:` to `2026-06-20`.
- Root `CLAUDE.md` L3: set `Last verified:` to `2026-06-20`.

**Step 3: Commit**
```bash
git add CLAUDE.md apps/identity-wallet/CLAUDE.md
git commit -m "docs: point root CLAUDE.md at just ios-* workflow; bump freshness dates"
```
<!-- END_TASK_3 -->

---

## Phase 3 Done When

- `apps/identity-wallet/CLAUDE.md` documents `ios-env.sh` + `just ios-postinit`/`ios-check`/`ios-dev`/`ios-build` (AC4.1).
- No doc instructs editing `.cargo/config.toml` or hardcoding an Xcode path; obsolete cc-wrapper entries removed/relabeled (AC4.2) — verified by the Task 2 grep.
- Both CLAUDE.md "Last verified/updated" dates are `2026-06-20` (AC4.3).
- All edits committed.
