# MM-143: Test Requirements

This document maps every acceptance criterion from MM-143 to a verification method: automated command, manual human verification, or design-doc verification. A developer can verify all ACs from this document alone.

Prerequisite for all checks: enter the Nix dev shell with `nix develop --impure --accept-flake-config` from the workspace root.

---

## Summary

| AC       | Description                              | Verification Type |
|----------|------------------------------------------|-------------------|
| AC1.1    | Frontend files exist                     | Automated         |
| AC1.2    | src-tauri files exist                    | Automated         |
| AC1.3    | SvelteKit 2.x / Svelte 5.x versions     | Automated         |
| AC1.4    | Tauri 2.x version                        | Automated         |
| AC2.1    | src-tauri in workspace members           | Automated         |
| AC2.2    | `cargo build` succeeds                   | Automated         |
| AC2.3    | `cargo clippy` passes                    | Automated         |
| AC2.4    | `cargo fmt --check` passes              | Automated         |
| AC2.5    | Existing crates unaffected               | Automated         |
| AC3.1    | App appears in iOS simulator             | Manual            |
| AC3.2    | Placeholder screen visible               | Manual            |
| AC3.3    | No crash on launch                       | Manual            |
| AC4.1    | Greet button triggers Rust command       | Manual            |
| AC4.2    | Rust response displayed in UI            | Manual            |
| AC4.3    | No JS console errors during IPC          | Manual            |
| AC4.4    | UI visible without scrolling (iPhone 15) | Manual            |
| AC5.1    | cargo-tauri in PATH after nix develop    | Automated         |
| AC5.2    | node 22.x in PATH after nix develop     | Automated         |
| AC5.3    | pnpm in PATH after nix develop          | Automated         |
| AC5.4    | CLAUDE.md exists with required content   | Automated         |
| AC5.5    | Root CLAUDE.md points to wallet CLAUDE.md| Automated         |
| AC5.6    | src-tauri/gen/ in .gitignore             | Automated         |
| AC6.1    | rust-check job documented                | Design-doc        |
| AC6.2    | frontend-check job documented            | Design-doc        |
| AC6.3    | Simulator testing excluded from CI noted | Design-doc        |

---

## AC1: Project directory structure exists

### AC1.1 — Frontend files exist (Automated)

Verify that all required frontend files are present at `apps/identity-wallet/`.

```bash
# Run from workspace root. All 7 files must exist (exit code 0 for each).
test -f apps/identity-wallet/package.json && \
test -f apps/identity-wallet/svelte.config.js && \
test -f apps/identity-wallet/vite.config.ts && \
test -f apps/identity-wallet/src/routes/+layout.ts && \
test -f apps/identity-wallet/src/routes/+layout.svelte && \
test -f apps/identity-wallet/src/routes/+page.svelte && \
test -f apps/identity-wallet/src/lib/ipc.ts && \
echo "AC1.1 PASS" || echo "AC1.1 FAIL"
```

### AC1.2 — src-tauri files exist (Automated)

Verify that all required Rust backend files are present at `apps/identity-wallet/src-tauri/`.

```bash
test -f apps/identity-wallet/src-tauri/Cargo.toml && \
test -f apps/identity-wallet/src-tauri/tauri.conf.json && \
test -f apps/identity-wallet/src-tauri/build.rs && \
test -f apps/identity-wallet/src-tauri/src/lib.rs && \
test -f apps/identity-wallet/src-tauri/src/main.rs && \
echo "AC1.2 PASS" || echo "AC1.2 FAIL"
```

### AC1.3 — SvelteKit 2.x and Svelte 5.x (Automated)

Verify version ranges declared in `package.json`.

```bash
# Check that @sveltejs/kit version starts with ^2
grep -q '"@sveltejs/kit": "\^2' apps/identity-wallet/package.json && \
# Check that svelte version starts with ^5
grep -q '"svelte": "\^5' apps/identity-wallet/package.json && \
echo "AC1.3 PASS" || echo "AC1.3 FAIL"
```

### AC1.4 — Tauri 2.x (Automated)

Verify Tauri dependency version in `src-tauri/Cargo.toml`.

```bash
# Check that tauri dependency is version 2 (e.g., tauri = "2" or tauri = "2.x.y")
grep -qE '^tauri = "2' apps/identity-wallet/src-tauri/Cargo.toml && \
echo "AC1.4 PASS" || echo "AC1.4 FAIL"
```

---

## AC2: Cargo workspace build succeeds

### AC2.1 — src-tauri in workspace members (Automated)

```bash
grep -q 'apps/identity-wallet/src-tauri' Cargo.toml && \
echo "AC2.1 PASS" || echo "AC2.1 FAIL"
```

### AC2.2 — cargo build succeeds (Automated)

```bash
cargo build 2>&1 && echo "AC2.2 PASS" || echo "AC2.2 FAIL"
```

### AC2.3 — cargo clippy passes (Automated)

```bash
cargo clippy --workspace -- -D warnings 2>&1 && echo "AC2.3 PASS" || echo "AC2.3 FAIL"
```

### AC2.4 — cargo fmt passes (Automated)

```bash
cargo fmt --all --check 2>&1 && echo "AC2.4 PASS" || echo "AC2.4 FAIL"
```

### AC2.5 — Existing crates unaffected (Automated)

Verify that the four original crates still build individually, confirming the new workspace member did not introduce errors.

```bash
cargo build --package relay && \
cargo build --package repo-engine && \
cargo build --package crypto && \
cargo build --package common && \
echo "AC2.5 PASS" || echo "AC2.5 FAIL"
```

---

## AC3: App launches in iOS simulator (Manual)

**Justification:** iOS simulator testing requires a physical macOS machine with Xcode, iOS Simulator platform, and Cocoapods installed. These cannot run in CI or be meaningfully automated.

**Prerequisites:**
1. macOS Ventura (13) or later
2. Xcode installed (latest stable from App Store)
3. iOS Simulator platform installed (Xcode -> Settings -> Platforms -> iOS)
4. Cocoapods installed: `sudo gem install cocoapods`
5. Inside the Nix dev shell (`nix develop --impure --accept-flake-config`)

**One-time setup (if not already done):**

```bash
cd apps/identity-wallet
pnpm install
cargo tauri ios init
```

**Steps:**

1. Open Xcode.app once to accept any pending license agreement.
2. Run from `apps/identity-wallet/`:
   ```bash
   cargo tauri ios dev
   ```
3. Wait for the Vite dev server to start and the Rust crate to compile for `aarch64-apple-ios-sim`. The iOS Simulator will open automatically.

**Verification checklist:**

### AC3.1 — App appears in iOS simulator
- [ ] After `cargo tauri ios dev` completes, an app window appears in the iOS Simulator.
- **PASS** if the app window is visible. **FAIL** if the simulator opens but no app launches, or if the command errors out before the simulator opens.

### AC3.2 — Placeholder screen visible (not blank)
- [ ] The app displays the "Identity Wallet" heading and a Greet button with an input field.
- **PASS** if content is visible. **FAIL** if the screen is blank white, shows "about:blank", or displays an error page.

### AC3.3 — No crash on launch
- [ ] No crash dialog appears in the simulator after the app loads.
- [ ] The app remains responsive (does not freeze or hang).
- **PASS** if the app stays running for at least 10 seconds after launch. **FAIL** if a crash dialog appears or the app force-closes.

---

## AC4: IPC bridge functions correctly (Manual)

**Justification:** IPC verification requires tapping the Greet button in the iOS simulator and observing the WebView response. The WebView inspector (Safari Developer Tools) is needed to check for console errors. None of this can be automated without a GUI testing framework connected to the simulator.

**Prerequisites:** Same as AC3 (app must be running in the iOS simulator via `cargo tauri ios dev`).

**Steps:**

1. In the iOS Simulator, observe the input field. It should contain "World" by default.
2. Tap the **Greet** button.
3. Open Safari on macOS. Go to **Develop** menu -> **[Simulator name]** -> select the WebView to open the Web Inspector.

**Verification checklist:**

### AC4.1 — Greet button triggers the Rust greet command
- [ ] After tapping the Greet button, the UI updates (a response message appears below the button).
- **PASS** if a response appears. **FAIL** if tapping the button does nothing or throws a visible error.

### AC4.2 — Rust response displayed in the UI
- [ ] The text "Hello, World!" appears on screen after tapping Greet with the default "World" input.
- [ ] Change the input to a different name (e.g., "Alice"), tap Greet again, and verify "Hello, Alice!" appears.
- **PASS** if the correct greeting is displayed for any name. **FAIL** if the displayed text is wrong, empty, or an error message.

### AC4.3 — No JavaScript console errors during IPC
- [ ] In Safari Web Inspector's Console tab, there are zero error-level messages during and after tapping the Greet button.
- [ ] Warnings are acceptable; errors are not.
- **PASS** if the Console shows no red error entries during the IPC invocation. **FAIL** if any `Error` or `TypeError` appears.

### AC4.4 — UI visible without scrolling on iPhone 15
- [ ] In the iOS Simulator, select **Device** -> **iPhone 15** (or the default simulator if already iPhone 15).
- [ ] The heading ("Identity Wallet"), input field, Greet button, and response text are all visible on screen without scrolling.
- **PASS** if all four elements are visible simultaneously. **FAIL** if any element requires scrolling to reach.

---

## AC5: Dev environment and documentation

### AC5.1 — cargo-tauri in PATH (Automated)

This check must be run inside a fresh Nix dev shell.

```bash
nix develop --impure --accept-flake-config --command bash -c \
  'command -v cargo-tauri && cargo-tauri --version | grep -qE "^cargo-tauri-cli 2\." && echo "AC5.1 PASS" || echo "AC5.1 FAIL"'
```

**Note:** If the above command takes too long due to Nix evaluation, you can also verify manually:
1. Enter the dev shell: `nix develop --impure --accept-flake-config`
2. Run: `cargo-tauri --version`
3. Verify the output shows version 2.x.x.

### AC5.2 — Node.js 22.x in PATH (Automated)

```bash
nix develop --impure --accept-flake-config --command bash -c \
  'node --version | grep -qE "^v22\." && echo "AC5.2 PASS" || echo "AC5.2 FAIL"'
```

### AC5.3 — pnpm in PATH (Automated)

```bash
nix develop --impure --accept-flake-config --command bash -c \
  'command -v pnpm > /dev/null && echo "AC5.3 PASS" || echo "AC5.3 FAIL"'
```

### AC5.4 — CLAUDE.md exists with required content (Automated)

Verify the file exists and contains all five required topics: macOS/Xcode prerequisites, Cocoapods, `pnpm install`, `cargo tauri ios init`, `cargo tauri ios dev`.

```bash
test -f apps/identity-wallet/CLAUDE.md && \
grep -q "Xcode" apps/identity-wallet/CLAUDE.md && \
grep -q "Cocoapods" apps/identity-wallet/CLAUDE.md && \
grep -q "cocoapods" apps/identity-wallet/CLAUDE.md && \
grep -q "pnpm install" apps/identity-wallet/CLAUDE.md && \
grep -q "cargo tauri ios init" apps/identity-wallet/CLAUDE.md && \
grep -q "cargo tauri ios dev" apps/identity-wallet/CLAUDE.md && \
echo "AC5.4 PASS" || echo "AC5.4 FAIL"
```

### AC5.5 — Root CLAUDE.md points to wallet CLAUDE.md (Automated)

```bash
grep -q "apps/identity-wallet/CLAUDE.md" CLAUDE.md && \
echo "AC5.5 PASS" || echo "AC5.5 FAIL"
```

### AC5.6 — src-tauri/gen/ in .gitignore (Automated)

```bash
grep -q "src-tauri/gen" .gitignore && \
echo "AC5.6 PASS" || echo "AC5.6 FAIL"
```

---

## AC6: CI pipeline documented (Design-doc verification)

**Justification:** AC6 is satisfied by the existence and content of the design plan itself. No code changes or runtime verification are needed. The CI pipeline is documented but not implemented -- the developer wires it up in tangled.org CI separately.

**Design plan location:** `docs/design-plans/2026-03-14-MM-143.md`, section "Suggested CI Pipeline"

### AC6.1 — rust-check job documented

- [ ] Open `docs/design-plans/2026-03-14-MM-143.md` and locate the "Suggested CI Pipeline" section.
- [ ] Verify it specifies a `rust-check` job that includes:
  - `cargo fmt --all --check`
  - `cargo clippy --workspace -- -D warnings` (or equivalent `cargo clippy --workspace`)
  - `cargo build --workspace`
- **PASS** if all three commands are listed under `rust-check`.

**Automated shortcut:**

```bash
grep -q "rust-check" docs/design-plans/2026-03-14-MM-143.md && \
grep -q "cargo fmt" docs/design-plans/2026-03-14-MM-143.md && \
grep -q "cargo clippy" docs/design-plans/2026-03-14-MM-143.md && \
grep -q "cargo build" docs/design-plans/2026-03-14-MM-143.md && \
echo "AC6.1 PASS" || echo "AC6.1 FAIL"
```

### AC6.2 — frontend-check job documented

- [ ] Verify the "Suggested CI Pipeline" section specifies a `frontend-check` job that includes:
  - `pnpm install` in `apps/identity-wallet/`
  - `pnpm build`
- **PASS** if both commands are listed under `frontend-check`.

**Automated shortcut:**

```bash
grep -q "frontend-check" docs/design-plans/2026-03-14-MM-143.md && \
grep -q "pnpm install" docs/design-plans/2026-03-14-MM-143.md && \
grep -q "pnpm build" docs/design-plans/2026-03-14-MM-143.md && \
echo "AC6.2 PASS" || echo "AC6.2 FAIL"
```

### AC6.3 — Simulator testing excluded from CI

- [ ] Verify the design document explicitly states that mobile simulator testing is excluded from automated CI.
- **PASS** if the document contains language indicating simulator testing is manual/excluded.

**Automated shortcut:**

```bash
grep -qi "excluded from automated CI" docs/design-plans/2026-03-14-MM-143.md && \
echo "AC6.3 PASS" || echo "AC6.3 FAIL"
```

---

## Full Automated Verification Script

Run all automated checks in sequence from the workspace root (inside the Nix dev shell):

```bash
#!/usr/bin/env bash
set -euo pipefail

PASS=0
FAIL=0

check() {
  local ac="$1"
  shift
  if "$@" > /dev/null 2>&1; then
    echo "PASS: $ac"
    ((PASS++))
  else
    echo "FAIL: $ac"
    ((FAIL++))
  fi
}

echo "=== AC1: Project directory structure ==="
check "AC1.1" bash -c '
  test -f apps/identity-wallet/package.json &&
  test -f apps/identity-wallet/svelte.config.js &&
  test -f apps/identity-wallet/vite.config.ts &&
  test -f apps/identity-wallet/src/routes/+layout.ts &&
  test -f apps/identity-wallet/src/routes/+layout.svelte &&
  test -f apps/identity-wallet/src/routes/+page.svelte &&
  test -f apps/identity-wallet/src/lib/ipc.ts
'
check "AC1.2" bash -c '
  test -f apps/identity-wallet/src-tauri/Cargo.toml &&
  test -f apps/identity-wallet/src-tauri/tauri.conf.json &&
  test -f apps/identity-wallet/src-tauri/build.rs &&
  test -f apps/identity-wallet/src-tauri/src/lib.rs &&
  test -f apps/identity-wallet/src-tauri/src/main.rs
'
check "AC1.3" bash -c '
  grep -q "\"@sveltejs/kit\": \"\\^2" apps/identity-wallet/package.json &&
  grep -q "\"svelte\": \"\\^5" apps/identity-wallet/package.json
'
check "AC1.4" bash -c 'grep -qE "^tauri = \"2" apps/identity-wallet/src-tauri/Cargo.toml'

echo ""
echo "=== AC2: Cargo workspace build ==="
check "AC2.1" bash -c 'grep -q "apps/identity-wallet/src-tauri" Cargo.toml'
check "AC2.2" cargo build
check "AC2.3" cargo clippy --workspace -- -D warnings
check "AC2.4" cargo fmt --all --check
check "AC2.5" bash -c '
  cargo build --package relay &&
  cargo build --package repo-engine &&
  cargo build --package crypto &&
  cargo build --package common
'

echo ""
echo "=== AC5: Dev environment and documentation ==="
check "AC5.4" bash -c '
  test -f apps/identity-wallet/CLAUDE.md &&
  grep -q "Xcode" apps/identity-wallet/CLAUDE.md &&
  grep -q "Cocoapods" apps/identity-wallet/CLAUDE.md &&
  grep -q "pnpm install" apps/identity-wallet/CLAUDE.md &&
  grep -q "cargo tauri ios init" apps/identity-wallet/CLAUDE.md &&
  grep -q "cargo tauri ios dev" apps/identity-wallet/CLAUDE.md
'
check "AC5.5" bash -c 'grep -q "apps/identity-wallet/CLAUDE.md" CLAUDE.md'
check "AC5.6" bash -c 'grep -q "src-tauri/gen" .gitignore'

echo ""
echo "=== AC6: CI pipeline documented ==="
check "AC6.1" bash -c '
  grep -q "rust-check" docs/design-plans/2026-03-14-MM-143.md &&
  grep -q "cargo fmt" docs/design-plans/2026-03-14-MM-143.md &&
  grep -q "cargo clippy" docs/design-plans/2026-03-14-MM-143.md &&
  grep -q "cargo build" docs/design-plans/2026-03-14-MM-143.md
'
check "AC6.2" bash -c '
  grep -q "frontend-check" docs/design-plans/2026-03-14-MM-143.md &&
  grep -q "pnpm install" docs/design-plans/2026-03-14-MM-143.md &&
  grep -q "pnpm build" docs/design-plans/2026-03-14-MM-143.md
'
check "AC6.3" bash -c 'grep -qi "excluded from automated CI" docs/design-plans/2026-03-14-MM-143.md'

echo ""
echo "=== Manual verification required ==="
echo "SKIP: AC3.1 — App appears in iOS simulator (requires Xcode + iOS Simulator)"
echo "SKIP: AC3.2 — Placeholder screen visible (requires Xcode + iOS Simulator)"
echo "SKIP: AC3.3 — No crash on launch (requires Xcode + iOS Simulator)"
echo "SKIP: AC4.1 — Greet button triggers Rust command (requires Xcode + iOS Simulator)"
echo "SKIP: AC4.2 — Rust response displayed in UI (requires Xcode + iOS Simulator)"
echo "SKIP: AC4.3 — No JS console errors (requires Xcode + iOS Simulator + Safari Web Inspector)"
echo "SKIP: AC4.4 — UI visible without scrolling on iPhone 15 (requires Xcode + iOS Simulator)"

echo ""
echo "=== Dev shell tools (run inside nix develop) ==="
echo "NOTE: AC5.1, AC5.2, AC5.3 require a fresh Nix dev shell to verify."
echo "  Run: nix develop --impure --accept-flake-config"
echo "  Then: cargo-tauri --version  (expect 2.x.x)"
echo "  Then: node --version         (expect v22.x.x)"
echo "  Then: pnpm --version         (expect any version)"

echo ""
echo "=== Results ==="
echo "Automated: $PASS passed, $FAIL failed"
echo "Manual: 7 checks require iOS simulator verification (AC3.1-AC3.3, AC4.1-AC4.4)"
echo "Total: $((PASS + FAIL)) automated + 7 manual = $((PASS + FAIL + 7)) checks"
```

**Note on AC5.1-AC5.3:** These are marked "Automated" in the summary table because they can be verified with a single command, but they require entering a Nix dev shell first. The full verification script above prints a reminder to run them separately inside the dev shell. If you are already inside the dev shell, you can add these inline checks:

```bash
# Only works inside `nix develop --impure --accept-flake-config`
cargo-tauri --version | grep -qE "^cargo-tauri-cli 2\." && echo "AC5.1 PASS" || echo "AC5.1 FAIL"
node --version | grep -qE "^v22\." && echo "AC5.2 PASS" || echo "AC5.2 FAIL"
command -v pnpm > /dev/null && echo "AC5.3 PASS" || echo "AC5.3 FAIL"
```
