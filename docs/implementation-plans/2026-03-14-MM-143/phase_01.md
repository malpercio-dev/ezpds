# MM-143: Tauri Mobile Project Scaffolding — Phase 1: Project Scaffolding + Workspace Integration

**Goal:** Establish `apps/identity-wallet/` with a SvelteKit 2 + Svelte 5 static frontend and a stub Rust crate integrated into the Cargo workspace so `cargo build` and `pnpm build` both succeed.

**Architecture:** SvelteKit 2 frontend configured as a fully static SPA (adapter-static with `fallback: 'index.html'`, SSR disabled) — shaped to be loaded by Tauri's WebView in Phase 2. Stub Rust crate at `apps/identity-wallet/src-tauri/` declares `crate-type = ["staticlib", "cdylib", "rlib"]` to satisfy iOS/Android/desktop build requirements from day one. The crate inherits `version`, `edition`, and `publish` from `[workspace.package]`, matching how all existing crates are configured.

**Tech Stack:** SvelteKit 2, Svelte 5, TypeScript, Vite 5, pnpm, Rust (stable), Cargo workspace resolver v2

**Scope:** Phase 1 of 3 — infrastructure only. No tests. Verified by running `cargo build`, `cargo clippy`, `cargo fmt --check`, and `pnpm build`.

**Codebase verified:** 2026-03-14

---

## Acceptance Criteria Coverage

This phase implements and verifies operationally (no unit tests — infrastructure phase):

### MM-143.AC1: Project directory structure exists
- **MM-143.AC1.1 Success (partial):** `apps/identity-wallet/` contains `package.json`, `svelte.config.js`, `vite.config.ts`, `src/app.html`, `src/routes/+layout.ts`, `src/routes/+layout.svelte`, `src/routes/+page.svelte` — `src/lib/ipc.ts` is added in Phase 2
- **MM-143.AC1.2 Success (partial):** `apps/identity-wallet/src-tauri/` contains `Cargo.toml`, `src/lib.rs`, `src/main.rs` — `tauri.conf.json` and `build.rs` are added in Phase 2
- **MM-143.AC1.3 Success:** SvelteKit version is 2.x and Svelte version is 5.x (verified in `package.json`)

### MM-143.AC2: Cargo workspace build succeeds
- **MM-143.AC2.1 Success:** `apps/identity-wallet/src-tauri` appears in root `Cargo.toml` `[workspace] members`
- **MM-143.AC2.2 Success:** `cargo build` at workspace root completes without errors
- **MM-143.AC2.3 Success:** `cargo clippy --workspace -- -D warnings` passes
- **MM-143.AC2.4 Success:** `cargo fmt --all --check` passes
- **MM-143.AC2.5 Failure:** Adding `src-tauri` to workspace members does not introduce errors in existing crates (`relay`, `repo-engine`, `crypto`, `common`)

---

<!-- START_SUBCOMPONENT_A (tasks 1-2) -->

<!-- START_TASK_1 -->
### Task 1: Create SvelteKit 2 + Svelte 5 frontend project

**Verifies:** None (infrastructure task — operational verification only)

**Files:**
- Create: `apps/identity-wallet/package.json`
- Create: `apps/identity-wallet/svelte.config.js`
- Create: `apps/identity-wallet/vite.config.ts`
- Create: `apps/identity-wallet/tsconfig.json`
- Create: `apps/identity-wallet/src/app.html`
- Create: `apps/identity-wallet/src/routes/+layout.ts`
- Create: `apps/identity-wallet/src/routes/+layout.svelte`
- Create: `apps/identity-wallet/src/routes/+page.svelte`
- Generated: `apps/identity-wallet/pnpm-lock.yaml` (created automatically by `pnpm install`)

**Step 1: Create directories**

```bash
mkdir -p apps/identity-wallet/src/routes
```

**Step 2: Create `apps/identity-wallet/package.json`**

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

**Step 3: Create `apps/identity-wallet/svelte.config.js`**

Note: `out: 'dist'` aligns the build output directory with `tauri.conf.json`'s `frontendDist: "../dist"` setting (added in Phase 2).

```js
import adapter from '@sveltejs/adapter-static';
import { vitePreprocess } from '@sveltejs/vite-plugin-svelte';

/** @type {import('@sveltejs/kit').Config} */
const config = {
  preprocess: vitePreprocess(),
  kit: {
    adapter: adapter({
      // fallback: 'index.html' routes unmatched paths to index for client-side navigation (SPA mode)
      fallback: 'index.html',
      // out: 'dist' matches tauri.conf.json frontendDist: "../dist" (configured in Phase 2)
      out: 'dist',
    }),
  },
};

export default config;
```

**Step 4: Create `apps/identity-wallet/vite.config.ts`**

Phase 1 uses basic Tauri-compatible server settings. Phase 2 adds `clearScreen: false`, HMR config, and `envPrefix`.

```typescript
import { sveltekit } from '@sveltejs/kit/vite';
import { defineConfig } from 'vite';

export default defineConfig({
  plugins: [sveltekit()],
  server: {
    port: 5173,
    strictPort: true,
    // host: '0.0.0.0' allows the iOS simulator to reach this dev server over LAN
    host: '0.0.0.0',
  },
});
```

**Step 5: Create `apps/identity-wallet/tsconfig.json`**

`.svelte-kit/tsconfig.json` is generated automatically by SvelteKit when `pnpm build` (or `pnpm check`) runs. The `extends` field resolves after first build.

```json
{
  "extends": "./.svelte-kit/tsconfig.json",
  "compilerOptions": {
    "strict": true
  }
}
```

**Step 6: Create `apps/identity-wallet/src/routes/+layout.ts`**

```typescript
// Disable SSR and prerendering globally — Tauri apps have no web server.
// The frontend runs entirely in WKWebView (iOS) and loads files from disk.
export const ssr = false;
export const prerender = false;
```

**Step 7: Create `apps/identity-wallet/src/routes/+layout.svelte`**

Svelte 5 replaces `<slot />` with `{@render children()}`. The `children` prop is typed as `Snippet` from Svelte's type exports.

```svelte
<script lang="ts">
  import type { Snippet } from 'svelte';

  let { children }: { children: Snippet } = $props();
</script>

{@render children()}
```

**Step 8: Create `apps/identity-wallet/src/app.html`**

SvelteKit requires `src/app.html` as its HTML template — `pnpm build` will fail without it. The `%sveltekit.head%` and `%sveltekit.body%` placeholders are mandatory and injected by SvelteKit at build time.

```html
<!doctype html>
<html lang="en">
	<head>
		<meta charset="utf-8" />
		<meta name="viewport" content="width=device-width, initial-scale=1" />
		%sveltekit.head%
	</head>
	<body>
		<div style="display: contents">%sveltekit.body%</div>
	</body>
</html>
```

**Step 9: Create `apps/identity-wallet/src/routes/+page.svelte`**

Static placeholder only — the Greet button and IPC demo are added in Phase 2.

```svelte
<!-- Static placeholder — IPC demo (greet button) is added in Phase 2 -->
<h1>Identity Wallet</h1>
<p>Coming in Phase 2.</p>
```

**Step 10: Update `.gitignore` to exclude frontend build artifacts**

The workspace `.gitignore` is at `/Users/jacob.zweifel/workspace/malpercio-dev/ezpds/.gitignore`. Append these lines at the end of the file:

```
# SvelteKit / frontend build artifacts
apps/identity-wallet/.svelte-kit/
apps/identity-wallet/dist/
apps/identity-wallet/node_modules/
```

**Step 11: Install dependencies and verify build**

```bash
cd apps/identity-wallet
pnpm install
```

Expected: Installs without errors. `pnpm-lock.yaml` is created.

```bash
pnpm build
```

Expected: Builds without errors. Creates `apps/identity-wallet/dist/` containing `index.html` and static assets.

**Step 12: Commit**

```bash
# From workspace root
git add apps/identity-wallet/package.json \
        apps/identity-wallet/pnpm-lock.yaml \
        apps/identity-wallet/svelte.config.js \
        apps/identity-wallet/vite.config.ts \
        apps/identity-wallet/tsconfig.json \
        apps/identity-wallet/src/ \
        .gitignore
git commit -m "feat(MM-143): scaffold SvelteKit 2 + Svelte 5 frontend at apps/identity-wallet"
```
<!-- END_TASK_1 -->

<!-- START_TASK_2 -->
### Task 2: Create src-tauri stub Rust crate

**Verifies:** None (infrastructure task — workspace integration verification done in Task 3)

**Files:**
- Create: `apps/identity-wallet/src-tauri/Cargo.toml`
- Create: `apps/identity-wallet/src-tauri/src/lib.rs`
- Create: `apps/identity-wallet/src-tauri/src/main.rs`

**Step 1: Create directories**

```bash
mkdir -p apps/identity-wallet/src-tauri/src
```

**Step 2: Create `apps/identity-wallet/src-tauri/Cargo.toml`**

Phase 1 uses a stub with no external dependencies — `tauri`, `tauri-build`, and `tauri.conf.json` are added in Phase 2. The three crate-types are all needed from day one: `staticlib` for iOS, `cdylib` for Android, `rlib` for standard `cargo build` and the binary target.

Note: `[profile.release]` settings in workspace member crates are ignored by Cargo (only the workspace root's profile settings apply). They are included here per the design plan and serve as documentation for standalone builds.

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

**Step 3: Create `apps/identity-wallet/src-tauri/src/lib.rs`**

Stub — `#[tauri::command]` greet and Tauri Builder are added in Phase 2.

```rust
// Stub — greet command and Tauri builder are wired up in Phase 2.
pub fn run() {}
```

**Step 4: Create `apps/identity-wallet/src-tauri/src/main.rs`**

The `windows_subsystem` attribute prevents a console window on Windows release builds. Harmless on macOS/iOS (guarded by `cfg_attr`).

```rust
// Prevents a console window from appearing on Windows in release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    identity_wallet::run();
}
```

**⚠️ Do NOT run `cargo build` yet.** The crate is not in the workspace members list. Running `cargo build` now will not include `identity-wallet` and will not fail — but it also won't verify anything. Task 3 adds the crate to the workspace and runs the actual verification.
<!-- END_TASK_2 -->

<!-- END_SUBCOMPONENT_A -->

<!-- START_SUBCOMPONENT_B (tasks 3-3) -->

<!-- START_TASK_3 -->
### Task 3: Integrate src-tauri into Cargo workspace and add iOS targets

**Verifies:** MM-143.AC2.1, MM-143.AC2.2, MM-143.AC2.3, MM-143.AC2.4, MM-143.AC2.5

**Files:**
- Modify: `/Users/jacob.zweifel/workspace/malpercio-dev/ezpds/Cargo.toml` (add workspace member)
- Modify: `/Users/jacob.zweifel/workspace/malpercio-dev/ezpds/rust-toolchain.toml` (add iOS targets)

**Step 1: Add `apps/identity-wallet/src-tauri` to workspace members**

In `/Users/jacob.zweifel/workspace/malpercio-dev/ezpds/Cargo.toml`, the current `members` block is:

```toml
members = [
    "crates/relay",
    "crates/repo-engine",
    "crates/crypto",
    "crates/common",
]
```

Change it to:

```toml
members = [
    "crates/relay",
    "crates/repo-engine",
    "crates/crypto",
    "crates/common",
    "apps/identity-wallet/src-tauri",
]
```

**Step 2: Add iOS targets to `rust-toolchain.toml`**

In `/Users/jacob.zweifel/workspace/malpercio-dev/ezpds/rust-toolchain.toml`, the current `targets` line is:

```toml
targets = ["aarch64-apple-darwin", "x86_64-apple-darwin", "x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu"]
```

Replace it with a multi-line form that includes the two iOS targets:

```toml
targets = [
    "aarch64-apple-darwin",
    "x86_64-apple-darwin",
    "x86_64-unknown-linux-gnu",
    "aarch64-unknown-linux-gnu",
    "aarch64-apple-ios",
    "aarch64-apple-ios-sim",
]
```

**Step 3: Verify `cargo build` succeeds (verifies MM-143.AC2.2 and MM-143.AC2.5)**

Run from the workspace root:

```bash
cargo build
```

Expected: Builds all 5 workspace members (relay, repo-engine, crypto, common, identity-wallet) without errors. The `identity-wallet` crate compiles as staticlib + cdylib + rlib + binary.

If it fails, check:
- Path `apps/identity-wallet/src-tauri` matches the actual directory
- `lib.rs` and `main.rs` exist at the correct paths

**Step 4: Verify clippy passes (verifies MM-143.AC2.3)**

```bash
cargo clippy --workspace -- -D warnings
```

Expected: Zero warnings or errors across all workspace members.

**Step 5: Verify formatting (verifies MM-143.AC2.4)**

```bash
cargo fmt --all --check
```

Expected: Exits with code 0.

If it fails, run `cargo fmt --all` to fix formatting, then re-run `--check` to confirm.

**Step 6: Commit**

```bash
git add Cargo.toml rust-toolchain.toml apps/identity-wallet/src-tauri/
git commit -m "feat(MM-143): add src-tauri stub crate to workspace, add iOS targets to rust-toolchain"
```
<!-- END_TASK_3 -->

<!-- END_SUBCOMPONENT_B -->
