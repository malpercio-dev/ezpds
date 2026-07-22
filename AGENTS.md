# ezpds

Last verified: 2026-07-13

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
- `just bruno-check` - Verify route ⇄ Bruno-collection parity (scripts/bruno-parity.sh)
- `just font-check` - Verify the five vendored font copies haven't drifted (scripts/font-parity.sh; same-named font files must be byte-identical across copies)
- `just cap-check` - Verify the Tauri IPC capability allowlists stay minimal (scripts/capability-check.sh; no `core:default`, mobile schema, withGlobalTauri off — the static half of the least-privilege boundary in docs/security/tauri-ipc-boundary.md)
- `just ticket-ref-check` - Fail if Rust source carries a Linear ticket / AC reference in a comment (scripts/ticket-ref-check.sh; traceability belongs in `docs/`, not `.rs`)
- `just runbook-parity-check` - Guard the master-key disaster runbook against drift between its canonical copy (`docs/operations/master-key-disaster-runbook.md`) and its published, operator-facing rewrite on the docs site (`sites/docs/src/content/docs/operator/master-key-runbook.md`): the golden rule and quick-reference step ordering must read identical in both (scripts/runbook-parity-check.sh)
- `just auth-seam-check` - Verify every access-token verification routes through `auth::extractors::authenticate_access` (scripts/auth-seam-check.sh; a route/guard calling `verify_access_token` directly would skip the RFC 9449 DPoP scheme↔`cnf.jkt` binding enforcement)
- `just ssrf-client-check` - Verify the caller-influenced well-known handle resolver uses the SSRF-hardened HTTP client (scripts/ssrf-client-check.sh; a plain-client wiring is a reflected-SSRF sink)
- `just gc-guard-check` - Verify `just gc` never targets the real main working tree when run from a secondary worktree (scripts/gc-guard-check.sh; spins up a throwaway worktree and asserts the main checkout is skipped)
- `just ios-paths-check` - Verify the iOS workflows' `paths:` filters match the apps' cargo dependency graph exactly (scripts/ios-paths-check.sh; an unwatched app dependency or an entry re-widened to `crates/**` both fail — keeps pure-PDS changes from triggering the macOS lanes)
- `just ios-template-check` - Verify the forked XcodeGen iOS project template (scripts/ios/project.yml, rendered on every `cargo tauri ios init` via `bundle > iOS > template`) is in lockstep with the workflows' tauri-cli pin, still carries every workaround, and is referenced by both apps (scripts/ios-template-check.sh; Linux-runnable)
- `just deny` / `cargo deny check licenses bans sources` - Dependency license + supply-chain gate (policy in `deny.toml`; advisories stay with `cargo audit` to avoid double-reporting)
- `just ci` - Full local gate (fmt-check, lock-check, bruno-check, docs-check, changelog-check, changelog-test, font-check, cap-check, ticket-ref-check, runbook-parity-check, auth-seam-check, ssrf-client-check, gc-guard-check, ios-paths-check, swift-rs-check, ios-template-check, clippy, test, audit, deny) — the same checks CI runs
- `just harness-pds` - Spawn a hermetic local PDS (mock plc.directory, throwaway admin token, TLS-fronted) for the mobile apps' **browser test harness** proxy mode; prints the URL + token. Needs a built `pds` binary (`cargo build -p pds`). See the Mobile section.
- `just docs-screenshots` / `just docs-screenshots-check` - Regenerate (or drift-check) the docs sites' app imagery by Playwright-driving each mobile app's **browser test harness** (`VITE_HARNESS=fake`) across its named scenarios — happy + error/rare states — into `sites/docs/public/screenshots/`. Deterministic (frozen clock, no network) and Linux-runnable (no macOS/Tauri). Tooling in `tools/screenshots/`; the `-check` visual-diff is NOT part of `just ci` (cross-runner font rendering can differ). See `tools/screenshots/README.md`.
- `just interop-setup` / `just interop <args>` - Install deps for and run the interop CLI (`tools/interop/`) against a live deployment
- `just mcp-setup` / `just mcp <args>` / `just mcp-test` - Install deps for, run, and test the Custos MCP server (`tools/mcp/`); `mcp-test` runs the auth.md agent-auth conformance suite against a hermetic locally spawned PDS (the `just mcp-test` recipe itself is not part of `just ci`/`just ci-pds` — needs node/pnpm like the interop CLI — but the underlying suite runs in CI via `ci.yml`'s PDS gate, which points it at the `pds` binary that gate already built rather than invoking the recipe's own `cargo build -p pds`)
- `just mcp-sidecar-setup` / `just mcp-sidecar <args>` / `just mcp-sidecar-test` - Install deps for, run, and test the credential-forwarding **Streamable-HTTP MCP sidecar** (`tools/mcp-sidecar/`, the hosted Custos tier); `mcp-sidecar-test` runs both suites — the hermetic scaffold half (stub PDS on loopback, node-only; what `mcp-check.yml` runs in CI) and the MM-370 end-to-end half (spawns the real `pds` binary via the tools/mcp harness, mints a sovereign child, and drives `create_post` through the sidecar; needs `just mcp-setup` once) — still offline, not part of `just ci`. The sidecar single-sources the `tools/mcp` tool surface and forwards the caller's credential (ADR-0024)

## CI/CD

CI runs on **GitHub Actions**, split into a Linux **PDS** lane and a macOS **iOS** lane (the iOS app needs macOS + Xcode that Linux runners lack). Deploys are **not** run by CI — they use **Railway's native GitHub integration**: Railway is connected to the repo and builds/deploys the `Dockerfile` itself, so there is **no `railway up` and no Railway token in CI**.

**PDS (`.github/workflows/ci.yml`).** A `just ci-pds` test gate (the Linux gate — like `just ci` but `--exclude identity-wallet --exclude admin-companion`, since the iOS apps need the Apple/GTK toolchain absent in CI) runs on PRs to `main`, on push to `main`, on push to `production`, and on a weekly schedule (advisory freshness: `cargo audit` re-scans Cargo.lock against the RustSec DB even when the repo is idle — also the re-check cadence for `.cargo/audit.toml` ignores). The same job then runs the stdio MCP conformance suite (`tools/mcp/test/conformance.test.ts`, node/pnpm set up just for this step): it points `CUSTOS_MCP_TEST_PDS_BIN` at the `target/debug/pds` binary `just ci-pds`'s `cargo test --workspace` already built, so it doesn't pay for a second `cargo build -p pds`. A separate path-filtered **`nix-check.yml`** lane runs `nix flake check --impure --accept-flake-config` whenever `flake.nix`/`flake.lock`/`devenv.nix`/`nix/**` change, so a broken flake can no longer merge unnoticed. A second path-filtered **`mcp-check.yml`** lane (secret-free, node-only) runs on `tools/mcp/**` and `tools/mcp-sidecar/**` changes: it type-checks both MCP packages (catching a break in the shared `registerTools` surface the sidecar single-sources) and runs the sidecar's hermetic suite (stub PDS on loopback); the sidecar's MM-370 end-to-end suite (`pnpm test:e2e`) still stays out of CI because it also needs a built `pds` binary — folding it into the PDS lane too is a tracked follow-up. Both Railway environments use "Wait for CI", so the green check is the deploy gate:
- **staging** — Railway watches `main`; merging a PR deploys staging.
- **production** — Railway watches the `production` branch; promoting a release means advancing `production` to a `vX.Y.Z` tag (`just deploy-production <tag>`), never a `main` merge. A `verify-release` job on the `production` branch refuses any tip whose tag doesn't match the workspace version.

Release flow: `just set-version X.Y.Z` (PR) → merge → `just release` (cuts/pushes the `vX.Y.Z` tag) → `just deploy-production vX.Y.Z` (advances `production`). Litestream backs up the production SQLite DB. See [docs/deploy.md](docs/deploy.md).

**iOS (`.github/workflows/ios-testflight.yml`).** Builds the `identity-wallet` Tauri app on a free public-repo `macos-26` runner and uploads to TestFlight on every push to `main` (App Store Connect API-key signing; never runs on `pull_request`, keeping secrets off fork PRs). The build/upload core is shared `just` recipes (`ios-ipa`, `ios-upload`, `ios-release`) usable locally. The **admin-companion** operator console ships through its own parallel lane — `.github/workflows/admin-testflight.yml` + `just admin-ipa`/`admin-upload`/`admin-release`, triggered on `apps/admin-companion/**` — reusing every signing secret except its own bundle-id-bound provisioning profile (`IOS_MOBILE_PROVISION_ADMIN`). See [docs/ios-cicd.md](docs/ios-cicd.md).

**iOS PR gate (`.github/workflows/ios-pr-check.yml`).** Because the TestFlight lanes hold signing secrets and never run on `pull_request`, a secret-free PR lane validates both apps before merge: an ubuntu job runs the frontend type-check (`pnpm check`) and unit tests, and a `macos-26` job regenerates the Xcode project from the committed scripts/ios/project.yml template, runs postinit + ios-check (the template-seam gate — it fails loudly if the rendered project is missing any workaround), cross-compiles the app staticlib for `aarch64-apple-ios`, and runs the app's Rust unit tests on the macOS host target (the only CI lane that can compile these crates) via `just ios-pr-check` / `just admin-pr-check` — everything short of xcodebuild archiving/signing.

## Dev Environment
- Managed entirely by Nix flake + devenv; do not install tools globally
- direnv auto-activates via `.envrc` (`use flake . --impure --accept-flake-config`)
- **Always run `nix develop` from the workspace root**, not from a subdirectory — `CARGO_HOME` and `RUSTUP_HOME` resolve relative to devenv root
- Rust toolchain managed by **rustup** (not Nix's `rust-default`); pinned in `rust-toolchain.toml` to an **exact version** (currently 1.96.0 — not the moving `stable` channel, so local and CI never diverge on rustfmt/clippy; bump deliberately), with rustfmt + clippy + rust-analyzer + iOS targets. On first shell entry, `enterShell` runs `rustup toolchain install` automatically.
- Shell provides: just, cargo-audit, sqlite (runtime binary + dev headers/library for sqlx's libsqlite3-sys), pkg-config, cargo-tauri, node (22.x), pnpm, rustup, shellcheck, jq, cmake (needed by aws-lc-sys)
- `LIBSQLITE3_SYS_USE_PKG_CONFIG=1` is set automatically by devenv (links sqlx against Nix-provided SQLite instead of bundled)
- `DEVELOPER_DIR` and the Apple iOS toolchain are resolved dynamically by `apps/identity-wallet/scripts/ios-env.sh` (sourced by both `enterShell` and the Xcode Run Script, so CLI and Xcode builds agree; iOS-host `CC`/`AR`/linker overrides are gated on `EZPDS_IOS_BUILD=1`, so a plain `cargo build --workspace` / `cargo run -p pds` is unaffected). Full toolchain gotchas: [`apps/identity-wallet/AGENTS.md`](apps/identity-wallet/AGENTS.md).
- Binary cache: devenv.cachix.org (activated by `--accept-flake-config`); speeds up cold shell builds significantly
- nixpkgs pin: `cachix/devenv-nixpkgs/rolling` (devenv's own nixpkgs fork — package versions may differ from upstream nixpkgs.search.dev)

## Project Structure
- `apps/identity-wallet/` - Tauri v2 mobile app (iOS) — Obsign identity wallet
- `apps/admin-companion/` - Tauri v2 mobile app (iOS) — operator console ("Brass Console")
- `crates/pds/` - PDS / Custos server (axum-based)
- `crates/repo-engine/` - ATProto repo engine
- `crates/crypto/` - Cryptographic operations (P-256 key generation, did:key derivation, AES-256-GCM encryption, did:plc genesis ops and verification)
- `crates/common/` - Shared types and utilities
- `nix/` - Nix deployment (module.nix: NixOS module for OCI container)
- `sites/marketing/` - Static marketing site for Obsign + Custos (zero-build HTML/CSS; design derivation documented in its README)
- `tools/interop/` - Node/pnpm interop CLI exercising a live deployment (staging by default) end-to-end against the real ATProto network (see its README)
- `tools/mcp/` - Custos MCP: first-party MCP stdio server (Node/TypeScript, pnpm) that self-onboards to a Custos PDS via the auth.md agent flow and exposes it as tools; its `pnpm test` conformance suite spawns a hermetic local PDS (see its README)
- `tools/mcp-sidecar/` - Credential-forwarding **Streamable-HTTP** MCP sidecar (`mcp.obsign.org`, the hosted Custos tier): single-sources the `tools/mcp` tool surface, swaps stdio → HTTP and the singleton session → a per-caller in-memory map, and forwards the caller's OAuth bearer per request while caching nothing durable (ADR-0023/0024). Deploys as a third Railway service; its `pnpm test` suite is hermetic (stub PDS on loopback). See its README
- `tools/screenshots/` - Playwright-driven docs screenshots (`just docs-screenshots`): boots each mobile app's browser harness in fake mode and captures deterministic per-scenario PNGs (happy + error/rare states) into `sites/docs/public/screenshots/`, so docs imagery can't go stale (see its README)
- `docs/` - Specs, design plans, implementation plans, and `docs/architecture/` (living architecture docs + the ADR log in `docs/architecture/decisions/`). Plans for landed/superseded work live in `docs/archive/` — when a plan's work ships, move its design/test/implementation triad there together (see `docs/archive/README.md`; a weekly Claude routine flags shipped-but-unarchived plans — see [`docs/operations/scheduled-agents.md`](docs/operations/scheduled-agents.md)). A nightly "dream" routine picks one vertical slice of the repo and PRs documentation consolidation/clarity fixes for morning review — see [`docs/operations/dream-routine.md`](docs/operations/dream-routine.md)

## Mobile

- `apps/identity-wallet/` — Tauri v2 iOS app (SvelteKit 2 + Svelte 5 frontend, Rust backend)
- **Browser test harness** — both mobile apps run in a plain desktop browser with no simulator: the Tauri `invoke()` seam is intercepted by `mockIPC` and backed by a stateful in-memory fake (scriptable via a `window.__harness` console API) or a proxy mode against a hermetic local PDS (`just harness-pds`). This is how an agent drives every screen and reproduces error states. Start with `pnpm --dir apps/identity-wallet dev:harness` / `pnpm --dir apps/admin-companion dev:harness` (or the `.claude/launch.json` `*-harness` configs). Full runbook in each app's AGENTS.md "Browser test harness" section; design + ACs in [docs/archive/design-plans/2026-07-12-browser-harness.md](docs/archive/design-plans/2026-07-12-browser-harness.md).
- Developer setup and iOS workstation guide: see [`apps/identity-wallet/AGENTS.md`](apps/identity-wallet/AGENTS.md)
- iOS build commands: `just ios-dev` / `just ios-build` (run from repo root; macOS + Xcode required). Toolchain resolved by `apps/identity-wallet/scripts/ios-env.sh`. The Xcode-project workarounds live in the committed XcodeGen template `scripts/ios/project.yml` (rendered by every `cargo tauri ios init` via `bundle > iOS > template`); run `just ios-postinit` after each init (swift-rs fork check + app icon + full verification).
- The per-app `scripts/ios-{env,postinit,check}.sh` files are thin wrappers over ONE shared implementation in `scripts/ios/` (repo root) — each wrapper pins its app dir and recipe prefix (per-app framework lists live in each app's `tauri.conf.json` `bundle > iOS > frameworks`). Edit the shared scripts, never a wrapper copy.

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
- **Token layer (code):** `apps/identity-wallet/src/lib/styles/{tokens,fonts,base}.css` is the live design system — global OKLCH color/type/space/radius/motion tokens, self-hosted fonts (bundled in `static/fonts/`, no runtime CDN), and base styles. Imported once in `src/routes/+layout.svelte`. Components reference `var(--color-*)`, `var(--font-*)`, `var(--space-*)`, etc.; **never hardcode hex or px**. Every screen has been migrated — the `src/lib/components` + `src/routes` tree is hex-free. Shared UI primitives live in `src/lib/components/ui/` (`Button`, `TextField`, `Spinner`, `SealEmblem`, `OnboardingShell`, `UrgencyBadge`, `DiffRow`, `ScreenHeader`, `SkeletonCard`, `Toggle`); reuse them rather than re-styling. `ScreenHeader` is the home-surface chrome (optional circular back + title + optional right-aligned actions; `size="home"` for the root list), `SkeletonCard` the shimmer placeholder (`seal` adds the avatar circle). `Toggle` is the settings on/off switch — the whole row is a WAI-ARIA `switch` (≥44px target); state is carried by knob position + track fill/hollow (never colour alone), with a `prefers-reduced-motion` fallback.
- **Tooling:** design work runs through the `/impeccable` skill (it reads the targeted app's PRODUCT.md/DESIGN.md — pass the app path so it loads the right brief, e.g. `apps/admin-companion`); live-iteration mode is pre-configured for the wallet in `.impeccable/live/config.json`.

### admin-companion — *terminal-native operator console* ("The Brass Console")
- **What:** a separate iOS app for the relay **operator** (generate/share claim codes, pair/revoke admin devices via per-device Secure-Enclave signed requests). One global admin device key (Secure-Enclave-backed on real devices, software P-256 on macOS/simulator) pairs with **multiple relays at once** (staging + production), each registration independent and revocation per-relay. Distinct audience: technical operators, not end users. See [docs/archive/design-plans/2026-06-26-admin-companion-app.md](docs/archive/design-plans/2026-06-26-admin-companion-app.md) (Wave 7) and [ADR-0017](docs/architecture/decisions/0017-multi-relay-admin-pairings.md).
- **Register:** product, but the inverse of Obsign's lane — cool-slate dark ground, sealing-wax gold accent carried from Obsign, monospace-forward; reports the literal truth rather than hiding the machinery.
- **Anti-references (hard "don'ts"):** hacker cosplay / terminal kitsch · consumer-app friendliness (Obsign's lane) · crypto/web3 hype · enterprise dashboard / chart-soup · low-contrast dark-theme mush.
- **Status:** fully built out — multi-relay pairing (QR/manual, per-relay revocation), biometric-gated claim codes, and the full operator console (device management, account listing/detail, moderation, code inventory, in-flight transfer visibility/cancel, server health/metrics). The Brass Console design system (token layer + UI primitives) lives in `apps/admin-companion/src/lib/{styles,components/ui}/`, documented in the app's `DESIGN.md` §5. Still open: the on-simulator demo (needs a Mac/Xcode). Screen inventory, IPC surface, and the pairing document contract: [apps/admin-companion/AGENTS.md](apps/admin-companion/AGENTS.md).

## Flake Outputs
- `nixosModules.default` - NixOS module for PDS OCI container deployment (see `nix/AGENTS.md`)
- `devShells.<system>.default` - Development shell via devenv

## Bruno API Collection
- `bruno/` - Bruno HTTP client collection for all PDS endpoints
- Open in Bruno desktop app; select the `local` environment and set `adminToken` to your PDS admin token
- **Mandatory:** When adding, removing, or changing any route (path, method, request body, response shape, auth), update the corresponding `.bru` file in `bruno/`. New routes get a new `.bru` file with the next `seq` number.
- **CI-enforced (path coverage):** `just bruno-check` (`scripts/bruno-parity.sh`, part of `just ci`/`ci-pds`) fails the gate if a registered route has no matching `.bru` request or a `.bru` targets a removed route. It checks paths only — method/body/auth changes still rely on the rule above.

## Project Status / Planning
- **Milestone state:** **v0.1 — Mobile-Only PDS is COMPLETE (2026-07-13)** — validated live (official-app OAuth/posts/video, bsky.social migration round trip); see the closure banners in `docs/unified-milestone-map.md` and `docs/archive/2026-07-08-daily-driver-readiness-audit.md`. Current work targets post-v0.1 phases (v0.2+ in the milestone map).
- **Live status:** Linear is the source of truth. To see where the project stands, call `linear_wave_status` (team `MM`, `label_prefix: "Wave"`) — one call returns every wave with Done/In Progress/Backlog tallies and percent complete. Prefer this over manually scanning the backlog.
- For exhaustive label/wave scans use `linear_list_issues` with the `label` filter and `limit=50+`. `linear_search_issues` is relevance-ranked full-text search (good for keyword lookups, NOT for "list every issue in Wave N").
- **Static plan:** [`docs/v01-issue-plan.md`](docs/v01-issue-plan.md) is the original wave breakdown (does not track live Done/Backlog state — use Linear for that). [`docs/unified-milestone-map.md`](docs/unified-milestone-map.md) is the phase model (v0.1–v2.0+).
- Wave labels: Wave 2 (Auth), Wave 3 (Key Sovereignty), Wave 4 (Repo + Blobs), Wave 5 (Federation), Wave 7 (Hardening), Wave 8 (auth.md). Tag new issues with their wave on creation.
- **When creating a Linear issue, always set the project to `ezpds`** (team `MM` alone is not enough — the project field is frequently missed, and wave labels don't attach the issue to the project).
- **Capture before close.** Surveys, audits, and tiered recommendation lists produced during a design/research session must land somewhere durable — the design doc in `docs/design-plans/` or Linear issues — before the session ends. Findings that live only in conversation are lost at the next `/clear`.

## PDS Architecture

See [`crates/pds/AGENTS.md`](crates/pds/AGENTS.md) for PDS-specific module structure,
hard rules (route isolation, pattern comments, DB ownership), and step-by-step guides for
adding routes and DB queries.

## Conventions

- **Branch from a fresh base.** Before starting work on an issue, `git fetch origin main` and create the branch from `origin/main` — never from a possibly-stale local HEAD. If the issue depends on or overlaps sibling issues already marked Done in Linear, verify their PRs are actually in the branch base before concluding a feature is "missing". Treat "Linear says Done but the code isn't here" as a stop-and-verify signal (your base is probably stale), not a cue to build the missing piece.
- Workspace-level dependency versions in root Cargo.toml; crates use `{ workspace = true }`
- All crates share a single version (see `[workspace.package]` in Cargo.toml — bumped via `just set-version`) and edition (2021) via workspace.package
- publish = false (not intended for crates.io)
- **Dependency hygiene (CI-gated).** `just lock-check` (`cargo metadata --locked`) fails if `Cargo.lock` drifts from the manifests, so every dependency change surfaces as a reviewable `Cargo.lock` diff; `just audit` (`cargo audit`) scans the lockfile against the RustSec advisory DB on every CI run. Accepted/ignored advisories and their rationale live in [`.cargo/audit.toml`](.cargo/audit.toml) — never pass `--ignore` on the command line. `just deny` (`cargo deny`) is the complementary license + supply-chain gate: it enforces the [`deny.toml`](deny.toml) license allowlist, the duplicate-major version guard-bans (the crates root `Cargo.toml` comments deliberately keep single-major), and the allowed crate sources. It deliberately does **not** check advisories (that stays with `cargo audit`, so the same CVE is never double-reported). Every exception in `deny.toml` — an allowed weak-copyleft/data license, a version guard-ban — carries a rationale comment, the same discipline as `.cargo/audit.toml`. When a PR adds or bumps a dependency, explain why in the PR description.
- **No ticket or AC references in source code.** Do not add comments like `// MM-123`, `// AC2.1:`, or `// MM-84.AC3: description` to `.rs` files or AGENTS.md files. Design plans and test plans in `docs/` are the right home for ticket traceability. Source code comments should describe *why* in terms of the system, not which ticket required it.

## Boundaries
- Never edit: `flake.lock` by hand (managed by `nix flake update`)
- Never edit: `devenv.local.nix` is gitignored for local overrides only
- `flake.nix` is intentionally minimal: it exposes only the devenv `devShells.<system>.default` and `nixosModules.default` (no crane/rust-overlay inputs, no `packages.<system>.*` build outputs). The PDS binary is built via the root `Dockerfile` (`cargo build --release --locked -p pds`), not by Nix — deploy as an OCI image, not a Nix-built binary. See `docs/deploy.md`.
