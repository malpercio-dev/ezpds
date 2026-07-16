# Release/versioning recipes and the iOS/admin app lanes live in split files, imported
# here so `just <recipe>` and `just --list` see them as one namespace. This root keeps
# the daily cargo gates. NOTE: the iOS workflows' `paths:` filters and
# scripts/ios-paths-check.sh's INFRA list watch these imported files by name — add any
# new import to both in the same change (ios-paths-check failing is the forcing function).
import 'just/release.just'
import 'just/ios.just'

check:
    cargo check --workspace

build:
    cargo build --workspace

test:
    cargo test --workspace

fmt:
    cargo fmt --all

fmt-check:
    cargo fmt --all --check

# Lint all crates; all warnings (Clippy and rustc) are treated as errors
clippy:
    cargo clippy --workspace --all-targets -- -D warnings

run-pds:
    cargo run -p pds

# Build the Docker image locally (requires Docker)
docker-build:
    docker build -t pds:latest .

# Spawn a hermetic local PDS for the mobile apps' browser-harness proxy mode: mock
# plc.directory (no live network), throwaway admin token, ephemeral data dir. Prints the
# URL + token and the VITE_HARNESS_PDS_URL line to point a `dev:harness:proxy` server at.
# Needs a built pds binary (`cargo build -p pds`). Ctrl-C stops and wipes it.
# See apps/*/AGENTS.md "Browser test harness" and docs/design-plans/2026-07-12-browser-harness.md.
harness-pds:
    scripts/harness-pds.sh

# Reclaim disk: prune MERGED git worktrees (+ their multi-GB target/ caches) and
# merged/[gone] local branches. `gc` is a dry run (reports what it would remove);
# `gc-apply` actually removes. Only work provably already in main is touched —
# unmerged/in-review worktrees and branches are kept. See scripts/gc.sh.
gc:
    scripts/gc.sh

gc-apply:
    scripts/gc.sh --apply

# Security audit against the RustSec advisory database. Accepted/ignored advisories
# and their rationale live in .cargo/audit.toml (read automatically by cargo audit).
audit:
    cargo audit

# Dependency license + supply-chain gate (cargo-deny; policy in deny.toml). Checks the license
# allowlist, the duplicate-major version guard-bans, and crate sources. Advisories are NOT checked
# here — `just audit` (cargo-audit) owns the RustSec scan, so we don't double-report the same CVEs.
deny:
    cargo deny check licenses bans sources

# Verify Cargo.lock is in sync with the Cargo.toml manifests. `--locked` makes cargo
# error instead of silently regenerating the lockfile, so accidental dependency drift
# (an edited manifest with a stale lock) fails CI instead of being merged. `metadata`
# resolves the whole workspace — including the iOS app that the Linux ci-pds build
# excludes — so the lockfile is verified end-to-end even where it cannot be compiled.
lock-check:
    cargo metadata --locked --format-version 1 > /dev/null

# Verify route ⇄ Bruno parity: every route registered in crates/pds/src/app.rs has a
# matching request in bruno/, and no .bru targets a route that no longer exists. This
# is the automated backstop for the "Mandatory" rule in AGENTS.md (Bruno API Collection).
bruno-check:
    scripts/bruno-parity.sh

# Regenerate and verify the high-drift published references (registered routes,
# operator configuration, both mobile IPC registries, and workspace version).
docs-generate:
    node scripts/generate-docs-reference.mjs

docs-check:
    scripts/docs-check.sh

# Regenerate the docs sites' app imagery by Playwright-driving each mobile app's browser
# harness (VITE_HARNESS=fake) across its named scenarios — happy paths plus error/rare states
# (migration-in-flight, degraded-health, failNext-injected failures) — into
# sites/docs/public/screenshots/. Deterministic (frozen clock, no network) and Linux-runnable
# (no macOS/Tauri shell). Pass through flags, e.g. `just docs-screenshots --app admin`.
docs-screenshots *args:
    scripts/docs-screenshots.sh {{args}}

# Visual-diff gate: re-render every screenshot and fail if any drifts from the committed PNG
# (an unintended UI change) or is missing a baseline. Not part of `just ci` — cross-runner
# font rendering can differ; run it where the baselines were generated. Regenerate + commit
# with `just docs-screenshots` when a change is intentional.
docs-screenshots-check:
    scripts/docs-screenshots.sh --check

# Validate changelog fragment names/content and, when CHANGELOG_BASE_REF (or an explicit
# argument) identifies a PR base, require a fragment for changes to shipped surfaces.
changelog-check base="":
    scripts/changelog-check.sh {{base}}

# Hermetic regression coverage for the fragment gate and set-version roll-up.
changelog-test:
    scripts/changelog-test.sh

# Verify parity across the five vendored font copies (identity-wallet, admin-companion,
# PDS assets, marketing site, docs site): a font file bundled under the same name in more
# than one copy must be byte-identical everywhere, so a re-fetch or re-optimization of one
# copy cannot silently fork the brand type. Each copy may bundle a subset of the families.
font-check:
    scripts/font-parity.sh

# Verify the Tauri IPC capability allowlists stay minimal (no core:default), reference the
# mobile schema, and keep withGlobalTauri off. The static minimality-lock half of the
# least-privilege IPC boundary in docs/security/tauri-ipc-boundary.md (Tauri v2 has no runtime
# ACL-denial test); fails if an edit re-widens the surface. Runs on Linux — parses JSON only.
cap-check:
    scripts/capability-check.sh

# Fail if Rust source carries a Linear ticket / AC reference in a comment (AGENTS.md hard
# rule — traceability belongs in docs/, not `.rs`). #227 swept these out; #266 put sixteen
# back a day later. This is the forcing function so that regression can't recur silently.
ticket-ref-check:
    scripts/ticket-ref-check.sh

# Freeze the access-token binding seam: every access-token verification must go through
# auth::extractors::authenticate_access (the RFC 9449 scheme<->cnf.jkt enforcement). A route
# or guard calling auth::jwt::verify_access_token directly skips it — the MM-386 downgrade.
# Fails on any NEW direct call; guards.rs is baselined as the known-live MM-386 offender.
auth-seam-check:
    scripts/auth-seam-check.sh

# Guard the caller-influenced identity fetch against SSRF: resolveHandle's well-known
# fallback fetches a caller-controlled host, so it must use the SSRF-hardened HTTP client.
# Fails on a novel/un-hardened wiring; the plain-client wiring is baselined as MM-387.
ssrf-client-check:
    scripts/ssrf-client-check.sh

# Prove scripts/gc.sh never targets the real main working tree for pruning when run from a
# secondary worktree (the normal agent workflow) — regression guard for MM-390. Spins up a
# throwaway worktree, runs gc.sh dry-run from it, asserts the main checkout is skipped.
gc-guard-check:
    scripts/gc-guard-check.sh

# Verify the iOS workflows' `paths:` trigger filters match the apps' real dependency
# graph (cargo metadata), both directions: every in-repo crate an app links is watched
# (a new workspace-crate dependency can't ship without widening the filters), and no
# entry is broader than the graph (pure-PDS changes can't re-acquire the macOS lanes
# through a re-widened crates/** or scripts/**). Runs on Linux — reads metadata + YAML.
ios-paths-check:
    scripts/ios-paths-check.sh

# Verify the swift-rs --disable-sandbox fork ([patch.crates-io] in Cargo.toml) is both
# DECLARED and ACTUALLY APPLIED (Cargo.lock resolves swift-rs from the path, not the
# registry). Cargo silently stops applying a [patch] when a dependency bump requires a
# semver-incompatible swift-rs — this reads only Cargo.toml/Cargo.lock, so the Linux PR
# gate catches that before it breaks the macOS build with an EPERM far from the cause.
swift-rs-check:
    scripts/swift-rs-patch-check.sh

# Verify the forked XcodeGen iOS project template (scripts/ios/project.yml, wired via
# bundle > iOS > template in both apps' tauri.conf.json) is in lockstep with the
# tauri-cli version the workflows pin, still carries every required workaround, and is
# still referenced by both apps. Runs on Linux — greps only; the macOS-side
# `just ios-check`/`admin-check` verifies the same invariants in the GENERATED project.
ios-template-check:
    scripts/ios-template-check.sh

# Install dependencies for the interop CLI (tools/interop) — one-time setup.
interop-setup:
    cd tools/interop && pnpm install

# Run the interop CLI against a live deployment (default: staging). Exercises account
# provisioning, identity, sync, firehose, and scoped network interactions — see
# tools/interop/README.md for the runbook and the safety ground rules.
interop *args:
    tools/interop/bin/interop {{args}}

# Install dependencies for the Custos MCP server (tools/mcp) — one-time setup.
mcp-setup:
    cd tools/mcp && pnpm install

# Run the Custos MCP server (or `just mcp reset` to clear cached credentials).
# Configure via CUSTOS_PDS_URL / CUSTOS_MCP_EMAIL — see tools/mcp/README.md;
# MCP clients should launch tools/mcp/bin/custos-mcp directly.
mcp *args:
    tools/mcp/bin/custos-mcp {{args}}

# Run the auth.md agent-auth conformance suite (client half of the Wave 8 story):
# spawns a hermetic local PDS (built here first; plc.directory is mocked, nothing
# touches the live network) and drives discovery → register → claim → exchange →
# tool calls through the real MCP server. See tools/mcp/README.md.
mcp-test:
    cargo build -p pds
    cd tools/mcp && pnpm test

# Install dependencies for the credential-forwarding MCP sidecar (tools/mcp-sidecar)
# — one-time setup. The sidecar single-sources the tool surface from tools/mcp, so
# run `just mcp-setup` too (it provides tools.ts's transitive deps at runtime).
mcp-sidecar-setup:
    cd tools/mcp-sidecar && pnpm install

# Run the MCP sidecar (Streamable-HTTP, credential-forwarding). Requires
# MCP_SIDECAR_PDS_ORIGIN (and, in prod, MCP_SIDECAR_PUBLIC_ORIGIN) — see
# tools/mcp-sidecar/README.md. A long-running HTTP service, not a stdio launcher.
mcp-sidecar *args:
    tools/mcp-sidecar/bin/custos-mcp-sidecar {{args}}

# Run the sidecar scaffold suite: per-caller registry, credential forwarding,
# in-memory-only sessions, redaction, transport, and config parsing. Hermetic
# (stub PDS on loopback — no cargo build, no live network). See its README.
mcp-sidecar-test:
    cd tools/mcp-sidecar && pnpm test

# Shared gate list both `ci` variants run before their clippy/test/audit/deny tail.
# Adding a check here covers `just ci` (macOS/full) and `just ci-pds` (Linux) at once —
# the old design re-stated all twelve checks in each, so a gate added to one and
# forgotten in the other was a silent gap.
checks: fmt-check lock-check bruno-check docs-check changelog-check changelog-test font-check cap-check ticket-ref-check auth-seam-check ssrf-client-check gc-guard-check ios-paths-check swift-rs-check ios-template-check

# Run the full CI pipeline locally (all crates; use on macOS where the iOS app builds)
ci: checks clippy test audit deny

# CI gate for the Linux pds pipeline (GitHub Actions, .github/workflows/ci.yml). Excludes the
# iOS apps (identity-wallet, admin-companion), which need the Apple toolchain (security-framework)
# absent in CI; the mobile apps are built and checked via `just ios-*` / `just admin-*` on macOS.
ci-pds: checks
    cargo clippy --workspace --exclude identity-wallet --exclude admin-companion --all-targets -- -D warnings
    cargo test --workspace --exclude identity-wallet --exclude admin-companion
    just audit
    just deny

# Validate that the flake evaluates correctly (devShells + nixosModules).
nix-check:
    nix flake check --impure --accept-flake-config
