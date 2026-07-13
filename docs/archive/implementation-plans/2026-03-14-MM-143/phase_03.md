# MM-143: Tauri Mobile Project Scaffolding — Phase 3: Nix Dev Environment + Gitignore + Documentation

**Goal:** Add `cargo-tauri`, `nodejs_22`, and `pnpm` to the Nix dev shell; exclude the Tauri-generated Xcode project from git; and document the iOS developer setup.

**Architecture:** Three infrastructure changes — devenv.nix package additions following the existing `pkgs.*` list pattern, a `.gitignore` entry for `apps/identity-wallet/src-tauri/gen/`, and two AGENTS.md documents (new `apps/identity-wallet/AGENTS.md` + pointer section in root `AGENTS.md`) following the `nix/AGENTS.md` domain-level documentation pattern.

**Tech Stack:** Nix (devenv.nix, nixpkgs rolling via `cachix/devenv-nixpkgs/rolling`)

**Scope:** Phase 3 of 3 — pure infrastructure and documentation. No code compilation. Verified by checking `devenv.nix` contents and AGENTS.md existence.

**Codebase verified:** 2026-03-14

**AC6 note:** MM-143.AC6 (CI pipeline documented) is already satisfied — the design plan at `docs/design-plans/2026-03-14-MM-143.md` specifies the `rust-check` and `frontend-check` jobs in the "Suggested CI Pipeline" section. No code changes are required for AC6.

---

## Acceptance Criteria Coverage

This phase implements and verifies operationally:

### MM-143.AC5: Dev environment and documentation
- **MM-143.AC5.1 Success:** `cargo-tauri` is available in PATH after `nix develop --impure --accept-flake-config`
- **MM-143.AC5.2 Success:** `node` (22.x) is available in PATH after `nix develop`
- **MM-143.AC5.3 Success:** `pnpm` is available in PATH after `nix develop`
- **MM-143.AC5.4 Success:** `apps/identity-wallet/AGENTS.md` exists and covers: macOS/Xcode prerequisites, Cocoapods installation, `pnpm install` first-time setup, `cargo tauri ios init` first-time setup, and `cargo tauri ios dev` development workflow
- **MM-143.AC5.5 Success:** Root `AGENTS.md` contains a pointer to `apps/identity-wallet/AGENTS.md`
- **MM-143.AC5.6 Success:** `apps/identity-wallet/src-tauri/gen/` is listed in `.gitignore`

### MM-143.AC6: CI pipeline documented (already satisfied)
- **MM-143.AC6.1, AC6.2, AC6.3:** Verified by the design plan at `docs/design-plans/2026-03-14-MM-143.md` (Suggested CI Pipeline section). No implementation tasks required.

---

<!-- START_SUBCOMPONENT_A (tasks 1-4) -->

<!-- START_TASK_1 -->
### Task 1: Add cargo-tauri, nodejs_22, and pnpm to devenv.nix

**Verifies:** MM-143.AC5.1 (cargo-tauri in PATH), MM-143.AC5.2 (node 22.x in PATH), MM-143.AC5.3 (pnpm in PATH)

**Files:**
- Modify: `/Users/malpercio/workspace/malpercio-dev/ezpds/devenv.nix`

**Step 1: Update the `packages` list in `devenv.nix`**

The current `packages` list (lines 8-13) is:

```nix
  packages = [
    pkgs.just
    pkgs.cargo-audit
    pkgs.sqlite
    pkgs.pkg-config
  ];
```

Change it to (three new entries appended):

```nix
  packages = [
    pkgs.just
    pkgs.cargo-audit
    pkgs.sqlite
    pkgs.pkg-config
    pkgs.cargo-tauri
    pkgs.nodejs_22
    pkgs.pnpm
  ];
```

Verified nixpkgs attribute names (from `cachix/devenv-nixpkgs/rolling`):
- `pkgs.cargo-tauri` — Tauri CLI (version 2.9.6+)
- `pkgs.nodejs_22` — Node.js 22 LTS (underscore, not hyphen; no `_x` suffix)
- `pkgs.pnpm` — pnpm top-level package (moved from `nodePackages.pnpm` in nixpkgs 23.05+)

**Step 2: Validate Nix flake syntax**

```bash
just nix-check
```

Expected: Flake check passes without errors. This validates the Nix expression is syntactically correct.

If `just` is not available outside the dev shell, run directly:

```bash
nix flake check --impure --accept-flake-config
```

**Step 3: Commit**

```bash
git add devenv.nix
git commit -m "feat(MM-143): add cargo-tauri, nodejs_22, pnpm to devenv.nix"
```

**Step 4: Manual verification (requires re-entering dev shell)**

After the commit, re-enter the dev shell to verify all three tools are available:

```bash
nix develop --impure --accept-flake-config
cargo-tauri --version   # expected: cargo-tauri 2.x.x (verifies AC5.1)
node --version          # expected: v22.x.x (verifies AC5.2)
pnpm --version          # expected: x.x.x (verifies AC5.3)
```

Note: Re-entering the dev shell may take several minutes on first run as Nix downloads and caches the new packages.
<!-- END_TASK_1 -->

<!-- START_TASK_2 -->
### Task 2: Add src-tauri/gen/ to .gitignore

**Verifies:** MM-143.AC5.6 (`apps/identity-wallet/src-tauri/gen/` in .gitignore)

**Files:**
- Modify: `/Users/malpercio/workspace/malpercio-dev/ezpds/.gitignore`

**Step 1: Append Tauri gen pattern to `.gitignore`**

The current `.gitignore` has 30 lines (Phase 1 may have already added the SvelteKit/frontend entries). Append at the end of the file:

```
# Tauri-generated Xcode project (machine-specific; regenerated per developer via `cargo tauri ios init`)
apps/identity-wallet/src-tauri/gen/
```

If Phase 1's frontend build artifact entries (`apps/identity-wallet/.svelte-kit/`, `apps/identity-wallet/dist/`, `apps/identity-wallet/node_modules/`) were not already added during Phase 1 execution, add them as well:

```
# SvelteKit / frontend build artifacts
apps/identity-wallet/.svelte-kit/
apps/identity-wallet/dist/
apps/identity-wallet/node_modules/

# Tauri-generated Xcode project (machine-specific; regenerated per developer via `cargo tauri ios init`)
apps/identity-wallet/src-tauri/gen/
```

**Step 2: Verify the entry is present**

```bash
grep "src-tauri/gen" .gitignore
```

Expected: Prints the line containing `apps/identity-wallet/src-tauri/gen/`.

**Step 3: Commit**

```bash
git add .gitignore
git commit -m "chore(MM-143): gitignore Tauri-generated Xcode project at src-tauri/gen/"
```
<!-- END_TASK_2 -->

<!-- START_TASK_3 -->
### Task 3: Create apps/identity-wallet/AGENTS.md

**Verifies:** MM-143.AC5.4 (AGENTS.md exists with all required sections)

**Files:**
- Create: `apps/identity-wallet/AGENTS.md`

**Step 1: Create `apps/identity-wallet/AGENTS.md`**

Modeled on `nix/AGENTS.md` (Purpose → Contracts → Dependencies → Key Decisions → Invariants → Key Files). Covers all AC5.4 requirements: macOS/Xcode prerequisites, Cocoapods, `pnpm install`, `cargo tauri ios init`, and `cargo tauri ios dev`.

```markdown
# Identity Wallet Mobile App

Last verified: 2026-03-14

## Purpose

Tauri v2 iOS application — SvelteKit 2 + Svelte 5 frontend running in a native WKWebView, communicating with a Rust backend exclusively through Tauri's IPC bridge. First frontend code in the repository.

## Contracts

### Frontend (SvelteKit 2 + Svelte 5)

**Exposes:**
- `src/lib/ipc.ts` — typed wrappers for all Tauri IPC commands; import these instead of calling `invoke()` directly
- `src/routes/+page.svelte` — root page (Greet IPC demo)

**Guarantees:**
- SSR is disabled globally (`ssr = false` in `src/routes/+layout.ts`); the frontend is a fully static SPA loaded from disk by WKWebView
- Build output lands in `dist/` (configured via `out: 'dist'` in `svelte.config.js`)
- Frontend calls Tauri commands only through `src/lib/ipc.ts` — no raw `invoke()` calls in page components

**Expects:**
- `pnpm install` has been run in `apps/identity-wallet/`
- Node.js 22.x is in PATH (provided by the Nix dev shell)

### Rust Backend (src-tauri/)

**Exposes:**
- `src/lib.rs::greet(name: String) -> String` — registered Tauri IPC command callable from the frontend via `invoke('greet', { name })`

**Guarantees:**
- `crate-type = ["staticlib", "cdylib", "rlib"]` supports iOS (staticlib), Android (cdylib), and normal cargo builds (rlib)
- `src/main.rs` is the desktop entry point; `src/lib.rs::run()` is the iOS/Android entry point (via `#[cfg_attr(mobile, tauri::mobile_entry_point)]`)
- `tauri.conf.json` configures the bundle identifier, dev URL (`http://localhost:5173`), and frontend dist path (`../dist`)

**Expects:**
- `tauri.conf.json` exists in `src-tauri/` before `cargo build` runs — the config is read at compile time by `generate_context!()`
- `cargo-tauri` is in PATH (provided by the Nix dev shell)
- Xcode and iOS Simulator are installed on the developer's macOS machine

## Dependencies

- Frontend → Rust backend (via Tauri IPC — `@tauri-apps/api/core` `invoke()`)
- Rust backend → Cargo workspace (inherits `version`, `edition`, `publish` from root `Cargo.toml`)
- `src-tauri/gen/` → NOT tracked in git; generated per-developer by `cargo tauri ios init` (gitignored)

## Prerequisites (macOS/iOS Development)

1. **macOS Ventura (13) or later**

2. **Xcode** (latest stable, from App Store)
   - After installing, open Xcode.app once to accept the license agreement — failing to do this causes `cargo tauri ios dev` to fail silently
   - Install the iOS Simulator platform: Xcode → Settings → Platforms → iOS

3. **Cocoapods** — Tauri's iOS build uses it to link native Apple frameworks:
   ```bash
   sudo gem install cocoapods
   ```

4. **Apple Developer account** — optional for Simulator; required for physical device (TestFlight/App Store) builds

## First-Time Setup

After cloning the repo, perform these steps once per developer machine:

```bash
# 1. Enter the Nix dev shell (provides cargo-tauri, node 22, pnpm)
nix develop --impure --accept-flake-config

# 2. Install frontend dependencies
cd apps/identity-wallet
pnpm install

# 3. Generate the Xcode project (output is in src-tauri/gen/apple/ — gitignored)
cargo tauri ios init
```

Note: `src-tauri/gen/` contains a machine-specific Xcode project. It is gitignored and must be re-generated on each developer machine. Do not commit it.

## Development Workflow

```bash
# Enter the dev shell if not already active
nix develop --impure --accept-flake-config

# Launch the app in the iOS Simulator
# This starts pnpm dev + compiles the Rust crate for aarch64-apple-ios-sim + opens the Simulator
cd apps/identity-wallet
cargo tauri ios dev
```

For a non-iOS build (CI or any machine without Xcode):

```bash
# From workspace root — builds all workspace crates including src-tauri for the host platform
cargo build
```

## Key Decisions

- **`adapter-static` + `ssr = false`**: Tauri WebViews load files from disk — there is no web server. SSR is meaningless and globally disabled.
- **`out: 'dist'` in svelte.config.js**: Matches `tauri.conf.json`'s `frontendDist: "../dist"`.
- **`TAURI_DEV_HOST` for HMR**: Tauri v2 automatically sets this env var to the machine's LAN IP when running `cargo tauri ios dev`. The iOS simulator connects to the Vite dev server over LAN, not localhost.
- **`generate_context!()` is compile-time**: `tauri.conf.json` must exist when `src-tauri/` is compiled — the macro embeds the config at compile time and will fail to compile if the file is missing.
- **`src-tauri/gen/` is gitignored**: The Xcode project generated by `cargo tauri ios init` is machine-specific. Committing it causes merge conflicts and bloats the repo.
- **`tauri` and `tauri-build` declared locally**: These crates are not in `[workspace.dependencies]` because no other workspace crate uses them. `serde` and `serde_json` use `{ workspace = true }` per the standard workspace pattern.

## Invariants

- `src/lib/ipc.ts` is the only file that calls `invoke()` directly; page components import from `ipc.ts`
- `tauri.conf.json` bundle identifier `dev.malpercio.identitywallet` must match the iOS provisioning profile for physical device builds
- `src-tauri/gen/` is never committed — regenerate with `cargo tauri ios init`
- `pnpm-lock.yaml` is committed and kept in sync with `package.json`

## Key Files

- `src-tauri/tauri.conf.json` — Tauri config: bundle ID, devUrl, frontendDist, window settings
- `src-tauri/src/lib.rs` — Tauri IPC commands and `run()` (mobile entry point)
- `src-tauri/src/main.rs` — Desktop entry point (calls `lib::run()`)
- `src/lib/ipc.ts` — Typed TypeScript wrappers for all Tauri IPC commands
- `src/routes/+layout.ts` — `ssr = false; prerender = false` (global SPA config)
- `svelte.config.js` — adapter-static with `out: 'dist'` (SPA mode, matches tauri.conf.json)
- `vite.config.ts` — Tauri-compatible Vite server (clearScreen, HMR via TAURI_DEV_HOST, envPrefix)
```

**Step 2: Commit**

```bash
git add apps/identity-wallet/AGENTS.md
git commit -m "docs(MM-143): add apps/identity-wallet/AGENTS.md with iOS developer setup"
```
<!-- END_TASK_3 -->

<!-- START_TASK_4 -->
### Task 4: Add Mobile section to root AGENTS.md

**Verifies:** MM-143.AC5.5 (root AGENTS.md contains pointer to apps/identity-wallet/AGENTS.md)

**Files:**
- Modify: `/Users/malpercio/workspace/malpercio-dev/ezpds/AGENTS.md`

**Step 1: Read the current root `AGENTS.md`**

The current `AGENTS.md` has these h2 sections in order:
1. `## Tech Stack`
2. `## Commands`
3. `## Dev Environment`
4. `## Project Structure`
5. `## Flake Outputs`
6. `## Bruno API Collection`
7. `## Conventions`
8. `## Boundaries`

**Step 2: Insert `## Mobile` between `## Project Structure` and `## Flake Outputs`**

Add the following section between the `## Project Structure` block and the `## Flake Outputs` heading:

```markdown
## Mobile

- `apps/identity-wallet/` — Tauri v2 iOS app (SvelteKit 2 + Svelte 5 frontend, Rust backend)
- Developer setup and iOS workstation guide: see [`apps/identity-wallet/AGENTS.md`](apps/identity-wallet/AGENTS.md)
```

Also update the `Last verified` line at the top of AGENTS.md to `Last verified: 2026-03-14` (it already shows this date, so no change needed).

**Step 3: Update `## Project Structure` to include `apps/`**

If the current `## Project Structure` section only lists `crates/`, `nix/`, and `docs/`, prepend the `apps/` entry:

```markdown
## Project Structure
- `apps/identity-wallet/` - Tauri v2 mobile app (iOS)
- `crates/relay/` - Web relay (axum-based)
- `crates/repo-engine/` - ATProto repo engine
- `crates/crypto/` - Cryptographic operations ...
- `crates/common/` - Shared types and utilities
- `nix/` - Nix packaging and deployment ...
- `docs/` - Specs, design plans, implementation plans
```

**Step 4: Update `## Dev Environment` shell tools list**

The current `## Dev Environment` section lists the tools the Nix shell provides (line starting with `- Shell provides:`). After Phase 3 Task 1 adds `cargo-tauri`, `nodejs_22`, and `pnpm` to devenv.nix, update this line to include them.

Find the line that reads:
```
- Shell provides: just, cargo-audit, sqlite (runtime binary + dev headers/library for sqlx's libsqlite3-sys), pkg-config
```

Change it to:
```
- Shell provides: just, cargo-audit, sqlite (runtime binary + dev headers/library for sqlx's libsqlite3-sys), pkg-config, cargo-tauri, node (22.x), pnpm
```

Also update the `Last verified` date if it needs updating.

**Step 5: Commit**

```bash
git add AGENTS.md
git commit -m "docs(MM-143): add Mobile section to root AGENTS.md, update Dev Environment and Project Structure"
```
<!-- END_TASK_4 -->

<!-- END_SUBCOMPONENT_A -->
