# MM-143: Tauri Mobile Project Scaffolding — Phase 2: Tauri Configuration + IPC Bridge

**Goal:** Wire up Tauri fully — `tauri.conf.json`, the `greet` Rust command, and the SvelteKit frontend page that calls it — so `cargo tauri ios dev` works end-to-end in an iOS simulator.

**Architecture:** The Rust crate at `apps/identity-wallet/src-tauri/` gains the Tauri builder (`run()`), one IPC command (`greet`), and the build script required to compile. The SvelteKit frontend gains a typed `invoke()` wrapper in `src/lib/ipc.ts` and a Greet button in `+page.svelte` using Svelte 5 runes. The Vite server is configured to expose the dev server to the iOS simulator via `TAURI_DEV_HOST` (Tauri v2's recommended approach — no `internal-ip` package needed).

**Tech Stack:** Tauri v2 (Rust), `@tauri-apps/api` v2 (TypeScript), Svelte 5 runes, Vite 5

**Scope:** Phase 2 of 3 — infrastructure and manual simulator verification. No automated unit tests. Verified by `cargo build --workspace` + `pnpm build` + manual `cargo tauri ios dev` in simulator.

**Codebase verified:** 2026-03-14

**Design discrepancy noted:** The design plan mentions `internal-ip` npm package for HMR. Tauri v2's current recommendation is to use the `TAURI_DEV_HOST` environment variable instead — Tauri sets this automatically to the machine's LAN IP when running `cargo tauri ios dev`. This eliminates the `internal-ip` dependency. The behavior is identical.

---

## Acceptance Criteria Coverage

This phase implements and verifies operationally:

### MM-143.AC1: Project directory structure exists
- **MM-143.AC1.1 Success (completes):** `apps/identity-wallet/src/lib/ipc.ts` created (completing the full file list from AC1.1)
- **MM-143.AC1.2 Success (completes):** `apps/identity-wallet/src-tauri/` now contains `tauri.conf.json` and `build.rs` (completing AC1.2)
- **MM-143.AC1.4 Success:** Tauri version is 2.x (verified in `src-tauri/Cargo.toml` `[dependencies]`)

### MM-143.AC3: App launches in iOS simulator (manual verification)
- **MM-143.AC3.1 Success:** `cargo tauri ios dev` completes and the app appears in the iOS simulator
- **MM-143.AC3.2 Success:** App displays a visible placeholder screen (not a blank white screen or error)
- **MM-143.AC3.3 Failure:** App does not crash on launch (no crash dialog in simulator)

### MM-143.AC4: IPC bridge functions correctly (manual verification)
- **MM-143.AC4.1 Success:** Pressing the Greet button triggers the Rust `greet` command via `invoke()`
- **MM-143.AC4.2 Success:** The Rust response (e.g., "Hello, World!") is displayed in the UI
- **MM-143.AC4.3 Failure:** No JavaScript console errors appear in the WebView inspector during IPC invocation
- **MM-143.AC4.4 Edge:** Greet button and response text are visible without scrolling on a standard iPhone 15 screen

---

<!-- START_SUBCOMPONENT_A (tasks 1-2) -->

<!-- START_TASK_1 -->
### Task 1: Add Tauri Rust dependencies, build.rs, and tauri.conf.json

**Verifies:** MM-143.AC1.2 (tauri.conf.json and build.rs exist), MM-143.AC1.4 (Tauri version 2.x in Cargo.toml)

**Files:**
- Modify: `apps/identity-wallet/src-tauri/Cargo.toml` (add tauri and tauri-build deps)
- Create: `apps/identity-wallet/src-tauri/build.rs`
- Create: `apps/identity-wallet/src-tauri/tauri.conf.json`
- Modify: `/Users/malpercio/workspace/malpercio-dev/ezpds/flake.nix` (scope `buildDepsOnly` to relay-only packages)

**IMPORTANT — ordering:** `tauri::generate_context!()` (added in Task 2) reads `tauri.conf.json` at compile time. Both `tauri.conf.json` and the `tauri-build` build script must exist BEFORE updating `lib.rs` in Task 2. Create all three files in this task, then verify `cargo build` succeeds with the Phase 1 stub `lib.rs` before proceeding to Task 2.

**Step 1: Update `apps/identity-wallet/src-tauri/Cargo.toml`**

Add `[dependencies]`, `[build-dependencies]`, and complete the package section. `serde` and `serde_json` are declared in `[workspace.dependencies]` (see root `Cargo.toml` lines 30-32) so they use `{ workspace = true }`. `tauri` and `tauri-build` are Tauri-specific and stay local per the design plan.

Replace the entire `Cargo.toml` with:

```toml
[package]
name = "identity-wallet"
version.workspace = true
edition.workspace = true
publish.workspace = true

[lib]
name = "identity_wallet"
path = "src/lib.rs"
# staticlib  → iOS static binary
# cdylib     → Android shared library
# rlib       → normal `cargo build` + integration tests
crate-type = ["staticlib", "cdylib", "rlib"]

[dependencies]
# Tauri-specific — declared locally (not in workspace.dependencies per design plan)
tauri = "2"
# serde/serde_json are in workspace.dependencies (root Cargo.toml lines 30-32)
serde = { workspace = true }
serde_json = { workspace = true }

[build-dependencies]
# Tauri-specific — declared locally
tauri-build = "2"

# Tauri-recommended release optimizations for mobile binary size.
# IMPORTANT: Cargo ignores [profile.*] in workspace member crates — these settings
# have NO EFFECT here because src-tauri is always built as a workspace member.
# They are included per the design plan as documentation of Tauri's recommendations.
# When iOS release binary size becomes a concern, move these to the root Cargo.toml's
# [profile.release] section (note: that will affect ALL workspace crates' release builds).
[profile.release]
strip = true
lto = true
opt-level = "z"
```

**Step 2: Create `apps/identity-wallet/src-tauri/build.rs`**

```rust
fn main() {
    tauri_build::build()
}
```

**Step 3: Create `apps/identity-wallet/src-tauri/tauri.conf.json`**

`beforeDevCommand` and `beforeBuildCommand` tell Tauri to start the Vite dev server automatically when running `cargo tauri ios dev`.

```json
{
  "$schema": "https://schema.tauri.app/config/2",
  "productName": "Identity Wallet",
  "version": "0.1.0",
  "identifier": "dev.malpercio.identitywallet",
  "build": {
    "devUrl": "http://localhost:5173",
    "frontendDist": "../dist",
    "beforeDevCommand": "pnpm dev",
    "beforeBuildCommand": "pnpm build"
  },
  "app": {
    "windows": [
      {
        "title": "Identity Wallet",
        "width": 400,
        "height": 600,
        "resizable": true
      }
    ],
    "security": {
      "csp": null
    }
  },
  "bundle": {
    "active": true
  }
}
```

**Step 4: Update `flake.nix` to scope `buildDepsOnly` to relay-related packages**

Adding `tauri = "2"` to the workspace means `buildDepsOnly` (which builds deps for ALL workspace members) would now attempt to compile Tauri's native dependencies — `webkit2gtk` on Linux, Apple frameworks on macOS — which are not in `commonArgs.buildInputs`. This breaks `nix build .#relay` and `just nix-check`.

Fix: scope `buildDepsOnly` to only the 4 relay-related packages.

In `/Users/malpercio/workspace/malpercio-dev/ezpds/flake.nix`, the current `cargoArtifacts` line (line 42) is:

```nix
        cargoArtifacts = craneLib.buildDepsOnly commonArgs;
```

Change it to:

```nix
        # Scope buildDepsOnly to relay-related crates only.
        # apps/identity-wallet/src-tauri uses Tauri (webkit2gtk on Linux, Apple frameworks
        # on macOS) which are not in commonArgs.buildInputs. Without this scope,
        # buildDepsOnly would attempt to compile Tauri's native deps and fail in Nix.
        cargoArtifacts = craneLib.buildDepsOnly (commonArgs // {
          cargoExtraArgs = "--package relay --package repo-engine --package crypto --package common";
        });
```

After editing, verify the Nix syntax is correct:

```bash
just nix-check
```

Expected: Flake check passes without errors.

**Step 5: Verify `cargo build` still succeeds with the Phase 1 stub**

The Phase 1 `lib.rs` has `pub fn run() {}` (no `generate_context!()` yet). The build script runs and processes `tauri.conf.json`. The stub lib compiles. This verifies the new deps resolve correctly.

```bash
cargo build
```

Expected: Builds without errors. This may take several minutes on first run as Tauri's dependency tree is large.

**Step 6: Commit**

```bash
git add apps/identity-wallet/src-tauri/Cargo.toml \
        apps/identity-wallet/src-tauri/build.rs \
        apps/identity-wallet/src-tauri/tauri.conf.json \
        flake.nix \
        Cargo.lock
git commit -m "feat(MM-143): add tauri deps and tauri.conf.json to src-tauri; scope flake buildDepsOnly"
```
<!-- END_TASK_1 -->

<!-- START_TASK_2 -->
### Task 2: Implement the greet command in lib.rs

**Verifies:** MM-143.AC2.2 (cargo build), MM-143.AC2.3 (clippy), MM-143.AC2.4 (fmt)

**Files:**
- Modify: `apps/identity-wallet/src-tauri/src/lib.rs`
- No changes to `apps/identity-wallet/src-tauri/src/main.rs` (Phase 1 version already calls `identity_wallet::run()` correctly)

**Step 1: Replace `apps/identity-wallet/src-tauri/src/lib.rs`**

`#[cfg_attr(mobile, tauri::mobile_entry_point)]` marks `run()` as the iOS/Android entry point. On mobile, the OS calls `run()` directly instead of `main()`. On desktop, `main()` (from `main.rs`) still calls `run()` as usual.

`generate_context!()` reads `tauri.conf.json` at compile time (the file must already exist — created in Task 1).

```rust
#[tauri::command]
fn greet(name: String) -> String {
    format!("Hello, {}!", name)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![greet])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
```

**Step 2: Verify `cargo build` succeeds (verifies MM-143.AC2.2)**

```bash
cargo build
```

Expected: All workspace members build without errors.

**Step 3: Verify clippy passes (verifies MM-143.AC2.3)**

```bash
cargo clippy --workspace -- -D warnings
```

Expected: Zero warnings or errors.

**Step 4: Verify formatting (verifies MM-143.AC2.4)**

```bash
cargo fmt --all --check
```

Expected: Exits with code 0. If it fails, run `cargo fmt --all` then re-check.

**Step 5: Commit**

```bash
git add apps/identity-wallet/src-tauri/src/lib.rs
git commit -m "feat(MM-143): implement greet IPC command in src-tauri"
```
<!-- END_TASK_2 -->

<!-- END_SUBCOMPONENT_A -->

<!-- START_SUBCOMPONENT_B (tasks 3-4) -->

<!-- START_TASK_3 -->
### Task 3: Add @tauri-apps/api, create ipc.ts, update vite.config.ts

**Verifies:** MM-143.AC1.1 (completes — ipc.ts now exists)

**Files:**
- Modify: `apps/identity-wallet/package.json` (add `@tauri-apps/api` to dependencies)
- Modify: `apps/identity-wallet/vite.config.ts` (add clearScreen, HMR config, envPrefix)
- Create: `apps/identity-wallet/src/lib/ipc.ts`

**Step 1: Add `@tauri-apps/api` to `apps/identity-wallet/package.json`**

`@tauri-apps/api` is a runtime dependency (not devDependency) because it runs in the WebView at runtime. Add a `"dependencies"` block to the existing `package.json`:

```json
{
  "name": "identity-wallet",
  "version": "0.0.1",
  "private": true,
  "type": "module",
  "scripts": {
    "dev": "vite dev",
    "build": "vite build",
    "preview": "vite preview",
    "check": "svelte-kit sync && svelte-check --tsconfig ./tsconfig.json",
    "check:watch": "svelte-kit sync && svelte-check --tsconfig ./tsconfig.json --watch"
  },
  "dependencies": {
    "@tauri-apps/api": "^2"
  },
  "devDependencies": {
    "@sveltejs/adapter-static": "^3.0.8",
    "@sveltejs/kit": "^2.20.4",
    "@sveltejs/vite-plugin-svelte": "^5.0.3",
    "svelte": "^5.25.8",
    "svelte-check": "^4.1.5",
    "tslib": "^2.8.1",
    "typescript": "^5.8.2",
    "vite": "^5.4.8"
  }
}
```

**Step 2: Replace `apps/identity-wallet/vite.config.ts`**

`TAURI_DEV_HOST` is set automatically by `cargo tauri ios dev` to the machine's LAN IP so the iOS simulator can connect to the Vite dev server. When this env var is unset (desktop dev or CI), the server falls back to `'0.0.0.0'` with no custom HMR config.

**Design discrepancies noted in this task:**
- The design plan mentions `internal-ip` npm package for HMR host detection. Tauri v2 provides `TAURI_DEV_HOST` for this purpose, which is simpler and has no extra dependency.
- The design plan specifies `envPrefix: ['VITE_', 'TAURI_']`. Tauri v2 uses `TAURI_ENV_*` as the prefix for its environment variables (e.g., `TAURI_ENV_PLATFORM`, `TAURI_ENV_FAMILY`), not bare `TAURI_*`. Using `'TAURI_ENV_'` is correct for Tauri v2.

```typescript
import { sveltekit } from '@sveltejs/kit/vite';
import { defineConfig } from 'vite';

export default defineConfig({
  plugins: [sveltekit()],
  // clearScreen: false surfaces Rust compiler errors in the terminal instead of clearing them
  clearScreen: false,
  server: {
    port: 5173,
    strictPort: true,
    // TAURI_DEV_HOST is set by `cargo tauri ios dev` to the machine's LAN IP;
    // the iOS simulator connects to the dev server over LAN, not localhost
    host: process.env.TAURI_DEV_HOST || '0.0.0.0',
    hmr: process.env.TAURI_DEV_HOST
      ? {
          protocol: 'ws',
          host: process.env.TAURI_DEV_HOST,
          port: 5173,
        }
      : undefined,
  },
  // Expose VITE_* and TAURI_ENV_* environment variables to the frontend
  envPrefix: ['VITE_', 'TAURI_ENV_'],
});
```

**Step 3: Create `apps/identity-wallet/src/lib/` directory**

```bash
mkdir -p apps/identity-wallet/src/lib
```

**Step 4: Create `apps/identity-wallet/src/lib/ipc.ts`**

Typed wrapper around Tauri's `invoke()`. The command name `'greet'` matches the Rust function name exactly (snake_case maps to snake_case). The argument key `name` matches the Rust function parameter name.

```typescript
import { invoke } from '@tauri-apps/api/core';

export const greet = (name: string): Promise<string> =>
  invoke('greet', { name });
```

**Step 5: Install updated dependencies and verify build**

```bash
cd apps/identity-wallet
pnpm install
pnpm build
```

Expected: `pnpm install` updates `pnpm-lock.yaml` with `@tauri-apps/api`. `pnpm build` succeeds (the `ipc.ts` module compiles even though it's not yet imported by any page).

**Step 6: Commit**

```bash
# From workspace root
git add apps/identity-wallet/package.json \
        apps/identity-wallet/pnpm-lock.yaml \
        apps/identity-wallet/vite.config.ts \
        apps/identity-wallet/src/lib/ipc.ts
git commit -m "feat(MM-143): add @tauri-apps/api, ipc.ts, update vite config for iOS HMR"
```
<!-- END_TASK_3 -->

<!-- START_TASK_4 -->
### Task 4: Update +page.svelte with Greet button and verify full build

**Verifies:** MM-143.AC4.4 (button and response text visible without scrolling on iPhone 15)

**Files:**
- Modify: `apps/identity-wallet/src/routes/+page.svelte`

**Step 1: Replace `apps/identity-wallet/src/routes/+page.svelte`**

Uses Svelte 5 runes: `$state()` for reactive variables. `onclick` (not `on:click`) is the Svelte 5 DOM event syntax. The centered layout ensures AC4.4 is met — all interactive elements fit within iPhone 15's 852pt height without scrolling.

```svelte
<script lang="ts">
  import { greet } from '$lib/ipc';

  let name = $state('World');
  let greetMsg = $state('');

  async function handleGreet() {
    greetMsg = await greet(name);
  }
</script>

<main>
  <h1>Identity Wallet</h1>
  <div class="greet-form">
    <input
      type="text"
      bind:value={name}
      placeholder="Enter a name"
    />
    <button onclick={handleGreet}>Greet</button>
  </div>
  {#if greetMsg}
    <p class="greeting">{greetMsg}</p>
  {/if}
</main>

<style>
  main {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    min-height: 100vh;
    padding: 1rem;
    font-family: system-ui, sans-serif;
    box-sizing: border-box;
  }

  .greet-form {
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
    width: 100%;
    max-width: 280px;
    margin-top: 1rem;
  }

  input,
  button {
    padding: 0.5rem;
    font-size: 1rem;
    border-radius: 4px;
    border: 1px solid #ccc;
    box-sizing: border-box;
    width: 100%;
  }

  button {
    cursor: pointer;
    background: #007aff;
    color: white;
    border-color: #007aff;
  }

  .greeting {
    margin-top: 1rem;
    font-size: 1.25rem;
  }
</style>
```

**Step 2: Verify pnpm build succeeds**

```bash
cd apps/identity-wallet
pnpm build
```

Expected: Builds without errors. The page compiles and the `$lib/ipc` import resolves correctly.

**Step 3: Commit**

```bash
# From workspace root
git add apps/identity-wallet/src/routes/+page.svelte
git commit -m "feat(MM-143): add Greet IPC demo to +page.svelte using Svelte 5 runes"
```
<!-- END_TASK_4 -->

<!-- END_SUBCOMPONENT_B -->

<!-- START_SUBCOMPONENT_C (tasks 5-5) -->

<!-- START_TASK_5 -->
### Task 5: Manual iOS simulator verification

**Verifies:** MM-143.AC3.1, MM-143.AC3.2, MM-143.AC3.3, MM-143.AC4.1, MM-143.AC4.2, MM-143.AC4.3

**This task cannot be automated** — it requires a macOS machine with Xcode and iOS Simulator.

**Prerequisites (must be installed before proceeding):**
1. Xcode (latest, from App Store) with iOS 17+ Simulator platform installed (Xcode → Settings → Platforms)
2. Cocoapods: `sudo gem install cocoapods`
3. `cargo-tauri` must be in PATH. **Choose one:**
   - **Recommended:** Run Phase 3 Task 1 first (adds `pkgs.cargo-tauri` to devenv.nix, then enter `nix develop --impure --accept-flake-config`)
   - **Alternative:** Install directly: `cargo install tauri-cli` (does not require Nix, but takes longer and is not pinned to the workspace version)

   Note: Phase 2 and Phase 3 are independent (both depend only on Phase 1). Phase 3 Task 1 can be completed before Phase 2 Task 5 without breaking anything.

**Step 1: First-time iOS project init (run once per developer machine)**

This generates `src-tauri/gen/apple/` (gitignored — machine-specific Xcode project).

```bash
cd apps/identity-wallet
cargo tauri ios init
```

Expected: Creates `src-tauri/gen/apple/` directory with Xcode project files.

**Step 2: Launch Xcode first (required for license acceptance)**

Open Xcode.app manually before running `cargo tauri ios dev`. If Xcode has a pending license agreement, `cargo tauri ios dev` will fail silently.

**Step 3: Run the app in iOS simulator**

```bash
cd apps/identity-wallet
cargo tauri ios dev
```

Expected: Tauri starts the Vite dev server (`pnpm dev` runs automatically via `beforeDevCommand`), compiles the Rust crate for `aarch64-apple-ios-sim`, and launches the app in the iOS simulator.

**Verification — AC3.1, AC3.2, AC3.3:**
- [ ] The app appears in the iOS Simulator (AC3.1)
- [ ] The screen shows "Identity Wallet" heading and a Greet button (AC3.2 — not blank)
- [ ] No crash dialog appears (AC3.3)

**Step 4: Test the IPC bridge**

In the simulator:
1. The input field shows "World" by default
2. Tap the **Greet** button

**Verification — AC4.1, AC4.2, AC4.3, AC4.4:**
- [ ] Tapping Greet triggers the Rust `greet` command (AC4.1)
- [ ] "Hello, World!" appears below the button (AC4.2)
- [ ] Open Safari → Develop → [Simulator] → inspect the WebView; zero console errors during button tap (AC4.3)
- [ ] All interactive elements (input, button, response) are visible without scrolling (AC4.4)

**If the app shows a blank white screen:** Check that `pnpm build` ran successfully in `apps/identity-wallet/` — the WebView loads from `dist/index.html`.

**If the Greet button does nothing:** Check that `tauri.conf.json`'s `identifier` matches the iOS bundle ID. Also verify the Rust command name `'greet'` in `ipc.ts` matches the `#[tauri::command]` function name in `lib.rs`.
<!-- END_TASK_5 -->

<!-- END_SUBCOMPONENT_C -->
