# ezpds

Last verified: 2026-06-30

## Tech Stack
- Language: Rust (pinned to an exact stable version in rust-toolchain.toml, currently 1.96.0)
- Build: Cargo workspace (resolver v2)
- Database: SQLite via sqlx 0.8 (runtime-tokio + sqlite features)
- Dev Environment: Nix flake + devenv (direnv integration via .envrc)
- Task Runner: just

## Commands
- `nix develop --impure --accept-flake-config` - Enter dev shell (flags required; --impure for devenv CWD detection, --accept-flake-config activates the Cachix binary cache in nixConfig — without it, a cold build takes 20+ minutes)
- `docker build -t pds .` / `just docker-build` - Build PDS OCI image
- `just nix-check` / `nix flake check --impure --accept-flake-config` - Validate NixOS module evaluation and flake structure
- `cargo build` - Build all crates
- `cargo test` - Run all tests
- `cargo clippy --workspace -- -D warnings` - Lint (warnings as errors)
- `cargo fmt --all --check` - Check formatting
- `just ci` - Full local gate (fmt-check, lock-check, clippy, test, audit) — the same checks CI runs

## CI/CD
CI runs on **GitHub Actions**, split into a Linux **PDS** lane and a macOS **iOS** lane (the iOS app needs macOS + Xcode that Linux runners lack). Deploys are **not** run by CI — they use **Railway's native GitHub integration**: Railway is connected to the repo and builds/deploys the `Dockerfile` itself, so there is **no `railway up` and no Railway token in CI**.

**PDS (`.github/workflows/ci.yml`).** A `just ci-pds` test gate (the Linux gate — like `just ci` but `--exclude identity-wallet --exclude admin-companion`, since the iOS apps need the Apple/GTK toolchain absent in CI) runs on PRs to `main`, on push to `main`, and on push to `production`. Both Railway environments use "Wait for CI", so the green check is the deploy gate:
- **staging** — Railway watches `main`; merging a PR deploys staging.
- **production** — Railway watches the `production` branch; promoting a release means advancing `production` to a `vX.Y.Z` tag (`just deploy-production <tag>`), never a `main` merge. A `verify-release` job on the `production` branch refuses any tip whose tag doesn't match the workspace version.

Release flow: `just set-version X.Y.Z` (PR) → merge → `just release` (cuts/pushes the `vX.Y.Z` tag) → `just deploy-production vX.Y.Z` (advances `production`). Litestream backs up the production SQLite DB. See [docs/deploy.md](docs/deploy.md).

**iOS (`.github/workflows/ios-testflight.yml`).** Builds the `identity-wallet` Tauri app on a free public-repo `macos-26` runner and uploads to TestFlight on every push to `main` (App Store Connect API-key signing; never runs on `pull_request`, keeping secrets off fork PRs). The build/upload core is shared `just` recipes (`ios-ipa`, `ios-upload`, `ios-release`) usable locally. The **admin-companion** operator console ships through its own parallel lane — `.github/workflows/admin-testflight.yml` + `just admin-ipa`/`admin-upload`/`admin-release`, triggered on `apps/admin-companion/**` — reusing every signing secret except its own bundle-id-bound provisioning profile (`IOS_MOBILE_PROVISION_ADMIN`). See [docs/ios-cicd.md](docs/ios-cicd.md).

## Dev Environment
- Managed entirely by Nix flake + devenv; do not install tools globally
- direnv auto-activates via `.envrc` (`use flake . --impure --accept-flake-config`)
- **Always run `nix develop` from the workspace root**, not from a subdirectory — `CARGO_HOME` and `RUSTUP_HOME` resolve relative to devenv root
- Rust toolchain managed by **rustup** (not Nix's `rust-default`); pinned in `rust-toolchain.toml` to an **exact version** (currently 1.96.0 — not the moving `stable` channel, so local and CI never diverge on rustfmt/clippy; bump deliberately), with rustfmt + clippy + rust-analyzer + iOS targets. On first shell entry, `enterShell` runs `rustup toolchain install` automatically.
- Shell provides: just, cargo-audit, sqlite (runtime binary + dev headers/library for sqlx's libsqlite3-sys), pkg-config, cargo-tauri, node (22.x), pnpm, rustup, shellcheck
- `LIBSQLITE3_SYS_USE_PKG_CONFIG=1` is set automatically by devenv (links sqlx against Nix-provided SQLite instead of bundled)
- `DEVELOPER_DIR` and the Apple iOS toolchain are resolved dynamically (no hardcoded Xcode paths): `enterShell` sources `apps/identity-wallet/scripts/ios-env.sh`, which runs `/usr/bin/xcode-select -p` to point `DEVELOPER_DIR` at the active Xcode (Nix's Darwin hooks otherwise clobber it to a stub SDK). The same script is sourced by the patched Xcode Run Script phase, so CLI and Xcode builds resolve the toolchain identically. iOS-host `CC`/`AR`/linker overrides are gated on `EZPDS_IOS_BUILD=1` (set only by the `just ios-*` recipes and the Xcode Run Script), so a plain `cargo build --workspace` / `cargo run -p pds` is unaffected.
- Binary cache: devenv.cachix.org (activated by `--accept-flake-config`); speeds up cold shell builds significantly
- nixpkgs pin: `cachix/devenv-nixpkgs/rolling` (devenv's own nixpkgs fork — package versions may differ from upstream nixpkgs.search.dev)

## Project Structure
- `apps/identity-wallet/` - Tauri v2 mobile app (iOS)
- `crates/pds/` - PDS / Custos server (axum-based)
- `crates/repo-engine/` - ATProto repo engine
- `crates/crypto/` - Cryptographic operations (P-256 key generation, did:key derivation, AES-256-GCM encryption, did:plc genesis ops and verification)
- `crates/common/` - Shared types and utilities
- `nix/` - Nix deployment (module.nix: NixOS module for OCI container)
- `docs/` - Specs, design plans, implementation plans

## Mobile

- `apps/identity-wallet/` — Tauri v2 iOS app (SvelteKit 2 + Svelte 5 frontend, Rust backend)
- Developer setup and iOS workstation guide: see [`apps/identity-wallet/CLAUDE.md`](apps/identity-wallet/CLAUDE.md)
- iOS build commands: `just ios-dev` / `just ios-build` (run from repo root; macOS + Xcode required). Toolchain resolved by `apps/identity-wallet/scripts/ios-env.sh`; patches re-applied via `just ios-postinit` after `cargo tauri ios init`.

## Design Context
The repo has **two UI surfaces, each with its own scoped design brief.** Read the brief for the app you're working on before any frontend design/UX work, and target `/impeccable` at that app's path so it loads the right brief:
- **identity-wallet** (Obsign) → root **[PRODUCT.md](PRODUCT.md)** + **[DESIGN.md](DESIGN.md)**.
- **admin-companion** → **[apps/admin-companion/PRODUCT.md](apps/admin-companion/PRODUCT.md)** + **[apps/admin-companion/DESIGN.md](apps/admin-companion/DESIGN.md)**.

The two are **siblings** — shared security rigor (practice-what-you-preach, WCAG 2.2 AAA, status never by color alone) — but **deliberately different registers**. Do not cross-apply one app's visual system to the other.

### identity-wallet (Obsign) — *humane security instrument* (Proton / 1Password lane)
- **Register:** product — design serves the task of holding and defending an identity.
- **Personality:** a *serious security instrument* in the humane **Proton / 1Password** lane — sovereign, precise, trustworthy. Gravitas comes from precision and restraint, not chrome.
- **Principles:** clarity is the security feature · calm under alarm · progressive disclosure of the cryptographic machinery · practice the assurance you preach · honest, never hype.
- **Anti-references (hard "don'ts"):** crypto/web3 hype · enterprise dashboard · playful/gamified · generic stock-iOS · Ledger-style dark-technical heaviness.
- **Accessibility:** target WCAG 2.2 AAA; urgency/status is never signalled by color alone (always paired with text + icon + position).
- **Token layer (code):** `apps/identity-wallet/src/lib/styles/{tokens,fonts,base}.css` is the live design system — global OKLCH color/type/space/radius/motion tokens, self-hosted fonts (bundled in `static/fonts/`, no runtime CDN), and base styles. Imported once in `src/routes/+layout.svelte`. Components reference `var(--color-*)`, `var(--font-*)`, `var(--space-*)`, etc.; **never hardcode hex or px**. Every screen has been migrated — the `src/lib/components` + `src/routes` tree is hex-free. Shared UI primitives live in `src/lib/components/ui/` (`Button`, `TextField`, `Spinner`, `SealEmblem`, `OnboardingShell`, `UrgencyBadge`, `DiffRow`); reuse them rather than re-styling.
- **Tooling:** design work runs through the `/impeccable` skill (it reads the targeted app's PRODUCT.md/DESIGN.md — pass the app path so it loads the right brief, e.g. `apps/admin-companion`); live-iteration mode is pre-configured for the wallet in `.impeccable/live/config.json`.

### admin-companion — *terminal-native operator console* ("The Brass Console")
- **What:** a separate iOS app for the relay **operator** (generate/share claim codes, pair/revoke admin devices via per-device Secure-Enclave signed requests). Distinct audience: technical operators, not end users. See [docs/design-plans/2026-06-26-admin-companion-app.md](docs/design-plans/2026-06-26-admin-companion-app.md) (Wave 7).
- **Register:** product, but the inverse of Obsign's lane — cool-slate dark ground, sealing-wax gold accent carried from Obsign, monospace-forward; reports the literal truth rather than hiding the machinery.
- **Anti-references (hard "don'ts"):** hacker cosplay / terminal kitsch · consumer-app friendliness (Obsign's lane) · crypto/web3 hype · enterprise dashboard / chart-soup · low-contrast dark-theme mush.
- **Status:** Phase 6 ([MM-190](https://linear.app/atbb/issue/MM-190/phase-6-companion-app-scaffold-admin-device-key-app)) scaffolded the Tauri app **and built the Brass Console design system**: the token layer (`apps/admin-companion/src/lib/styles/{tokens,fonts,base}.css`, forked OKLCH, every text pair verified WCAG 2.2 AAA) plus the canonical UI primitives in `apps/admin-companion/src/lib/components/ui/` (`Button`, `StatusChip`, `CodeOutput`, `DeviceRow`, `TextField`, `ScreenShell`), exercised at the `/preview` route and documented in `DESIGN.md` §5. Phase 7 (MM-194) added the pairing + request-signing client, and **Phase 8 (MM-195) landed the operator screens** — Pair, Home (biometric-gated claim code with Copy/iOS Share), Settings (label, relay URL, biometric toggle, unpair = server-side self-revoke), and the error-state matrix — plus the biometric (`tauri-plugin-biometric`) and share-sheet (`tauri-plugin-sharesheet`) mobile plugins. Still open: re-run `/impeccable document` in scan mode against `apps/admin-companion/` to emit the `.impeccable/design.json` sidecar, and the on-simulator demo (needs a Mac/Xcode). App-specific contracts: [apps/admin-companion/CLAUDE.md](apps/admin-companion/CLAUDE.md).

## Flake Outputs
- `nixosModules.default` - NixOS module for PDS OCI container deployment (see `nix/CLAUDE.md`)
- `devShells.<system>.default` - Development shell via devenv

## Bruno API Collection
- `bruno/` - Bruno HTTP client collection for all PDS endpoints
- Open in Bruno desktop app; select the `local` environment and set `adminToken` to your PDS admin token
- **Mandatory:** When adding, removing, or changing any route (path, method, request body, response shape, auth), update the corresponding `.bru` file in `bruno/`. New routes get a new `.bru` file with the next `seq` number.

## Project Status / Planning
- **Live status:** Linear is the source of truth. To see where the project stands, call `linear_wave_status` (team `MM`, `label_prefix: "Wave"`) — one call returns every wave with Done/In Progress/Backlog tallies and percent complete. Prefer this over manually scanning the backlog.
- For exhaustive label/wave scans use `linear_list_issues` with the `label` filter and `limit=50+`. `linear_search_issues` is relevance-ranked full-text search (good for keyword lookups, NOT for "list every issue in Wave N").
- **Static plan:** [`docs/v01-issue-plan.md`](docs/v01-issue-plan.md) is the original wave breakdown (does not track live Done/Backlog state — use Linear for that). [`docs/unified-milestone-map.md`](docs/unified-milestone-map.md) is the phase model (v0.1–v2.0+).
- Wave labels: Wave 2 (Auth), Wave 3 (Key Sovereignty), Wave 4 (Repo + Blobs), Wave 5 (Federation), Wave 7 (Hardening), Wave 8 (auth.md). Tag new issues with their wave on creation.

## PDS Architecture
See [`crates/pds/CLAUDE.md`](crates/pds/CLAUDE.md) for PDS-specific module structure,
hard rules (route isolation, pattern comments, DB ownership), and step-by-step guides for
adding routes and DB queries.

## Conventions
- Workspace-level dependency versions in root Cargo.toml; crates use `{ workspace = true }`
- All crates share version (0.1.0) and edition (2021) via workspace.package
- publish = false (not intended for crates.io)
- **Dependency hygiene (CI-gated).** `just lock-check` (`cargo metadata --locked`) fails if `Cargo.lock` drifts from the manifests, so every dependency change surfaces as a reviewable `Cargo.lock` diff; `just audit` (`cargo audit`) scans the lockfile against the RustSec advisory DB on every CI run. Accepted/ignored advisories and their rationale live in [`.cargo/audit.toml`](.cargo/audit.toml) — never pass `--ignore` on the command line. When a PR adds or bumps a dependency, explain why in the PR description.
- **No ticket or AC references in source code.** Do not add comments like `// MM-123`, `// AC2.1:`, or `// MM-84.AC3: description` to `.rs` files or CLAUDE.md files. Design plans and test plans in `docs/` are the right home for ticket traceability. Source code comments should describe *why* in terms of the system, not which ticket required it.

## Boundaries
- Never edit: `flake.lock` by hand (managed by `nix flake update`)
- Never edit: `devenv.local.nix` is gitignored for local overrides only
- `flake.nix` is intentionally minimal: it exposes only the devenv `devShells.<system>.default` and `nixosModules.default` (no crane/rust-overlay inputs, no `packages.<system>.*` build outputs). The PDS binary is built via the root `Dockerfile` (`cargo build --release --locked -p pds`), not by Nix — deploy as an OCI image, not a Nix-built binary. See `docs/deploy.md`.
