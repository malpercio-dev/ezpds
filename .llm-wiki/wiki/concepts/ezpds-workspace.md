---
type: concept
domain: engineering
created: 2026-06-22
updated: 2026-06-22
sources: [sources/SRC-2026-06-22-001, sources/SRC-2026-06-22-002]
---

# ezpds Workspace

The Cargo workspace for the ezpds project — an easy-to-host ATProto Personal Data Server.

## Structure

```
ezpds/
├── apps/identity-wallet/   — Tauri v2 iOS app (SvelteKit 2 + Svelte 5)
├── crates/relay/           — Axum-based web relay server
├── crates/crypto/          — P-256 keys, did:plc, Shamir, AES-256-GCM
├── crates/common/          — Shared types and utilities
├── crates/repo-engine/     — ATProto repo engine (stub)
├── nix/                    — NixOS deployment module
├── docs/                   — Specs, design plans, implementation plans
└── bruno/                  — Bruno HTTP client collection
```

## Tech Stack

- **Language**: Rust (stable channel via rust-toolchain.toml)
- **Build**: Cargo workspace (resolver v2)
- **Database**: SQLite via [[entities/sqlx|sqlx]] 0.8 (runtime-tokio + sqlite)
- **Dev Environment**: Nix flake + devenv (direnv integration)
- **Task Runner**: just

## Conventions

- Workspace-level dependency versions in root Cargo.toml; crates use `{ workspace = true }`
- All crates share version (0.1.0) and edition (2021) via workspace.package
- publish = false (not intended for crates.io)
- No ticket references in source code
- Mandatory Bruno API collection updates for route changes

## Related

- [[concepts/nix-dev-environment|Nix Dev Environment]]
- [[concepts/functional-core-imperative-shell|Functional Core / Imperative Shell]]
- [[sources/SRC-2026-06-22-001]] — Full project conventions
