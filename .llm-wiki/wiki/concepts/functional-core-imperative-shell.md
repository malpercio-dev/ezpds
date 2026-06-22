---
type: concept
domain: engineering
created: 2026-06-22
updated: 2026-06-22
sources: [sources/SRC-2026-06-22-001, sources/SRC-2026-06-22-003, sources/SRC-2026-06-22-004]
---

# Functional Core / Imperative Shell

The architectural pattern enforced across the [[concepts/ezpds-workspace|ezpds workspace]]. Separates pure business logic (Functional Core) from I/O boundaries (Imperative Shell).

## Pattern

- **Functional Core**: Pure functions, no side effects, no I/O. Given the same inputs, always produces the same outputs. Examples: [[entities/crypto|Crypto Crate]], [[entities/common|Common Crate]], `auth/jwt.rs`, `auth/password.rs`.
- **Imperative Shell**: Handles I/O — HTTP, database, process state. Orchestrates calls to Functional Core modules. Example: [[entities/relay|Relay Server]] (the only Imperative Shell in the workspace).
- **Mixed (unavoidable)**: Some modules straddle the boundary (e.g. `auth/dpop.rs` which needs both validation logic and a nonce store).

## Enforcement

Every `.rs` file with runtime behavior must have a pattern comment at the top:
```rust
// pattern: Functional Core
// pattern: Imperative Shell
// pattern: Mixed (unavoidable)
```

Files with only types, constants, or re-exports are exempt.

## In ezpds

| Crate | Pattern |
|-------|---------|
| `crates/crypto` | Functional Core |
| `crates/common` | Functional Core |
| `crates/repo-engine` | Functional Core (stub) |
| `crates/relay` | Imperative Shell |
| `crates/relay/src/auth/jwt.rs` | Functional Core |
| `crates/relay/src/auth/extractors.rs` | Imperative Shell |
| `crates/relay/src/auth/dpop.rs` | Mixed (unavoidable) |

## Related

- [[concepts/route-isolation|Route Isolation]]
- [[concepts/pattern-comments|Pattern Comments]]
- [[entities/relay|Relay Server]]
- [[entities/crypto|Crypto Crate]]
