# Relay Crate Refactoring Plan

**Date:** 2026-03-16
**Status:** Complete

## Context

Deep codebase scan revealed several patterns of duplication in the relay crate that increase maintenance burden and bug risk. The crypto, common, and workspace-level code are in good shape. This plan addresses relay-specific technical debt in priority order.

## P1: Extract Token Generation & Hashing Module

**Problem:** The pattern — generate 32 random bytes, base64url-encode, SHA-256 hash to hex — is copy-pasted 10+ times across route handlers and tests.

**Locations:**
- `create_mobile_account.rs:143-149` (device token)
- `create_mobile_account.rs:151-157` (session token)
- `register_device.rs:76-79` (device token)
- `create_did.rs:250-258` (session token)
- `create_handle.rs:321-323` (session token)
- `auth.rs:109-115` (decode+hash in `require_pending_session`)
- `auth.rs:177-184` (decode+hash in `require_session`)
- Plus ~8 more in test modules

**Solution:** New module `crates/relay/src/routes/token.rs` with:
- `generate_token() -> (String, String)` — returns (plaintext, hash)
- `sha256_hex(data: &[u8]) -> String` — reusable hex hashing
- `hash_token(base64url_token: &str) -> Result<String, ApiError>` — decode + hash for auth path

**Impact:** ~60 lines removed in production, ~40 in tests. Single source of truth for token format.

## P2: Centralize Unique Constraint Classification

**Problem:** Four divergent implementations parse SQLite's `"UNIQUE constraint failed: <table>.<column>"` message.

**Locations:**
- `create_account.rs:267` — `unique_violation_source()` returns `Option<UniqueConflict>`
- `create_mobile_account.rs:346` — `classify_pending_account_error()` parses table.column
- `create_did.rs:53` — `is_unique_violation()` boolean check
- `claim_codes.rs:121` — `is_unique_violation()` duplicate of above

**Solution:** New module `crates/relay/src/db/constraint.rs` with:
- `is_unique_violation(e: &sqlx::Error) -> bool`
- `unique_violation_column(e: &sqlx::Error, table: &str) -> Option<String>`

**Impact:** Single place to update if sqlx changes error format. Eliminates 4 independent parsers.

## P3: Extract Email/Handle Uniqueness Query Helpers

**Problem:** Identical OR EXISTS pre-flight queries duplicated across two handlers.

**Locations:**
- `create_account.rs:70-90` (email), `94-114` (handle)
- `create_mobile_account.rs:90-110` (email), `113-133` (handle)

**Solution:** Query helpers in a shared location (e.g., `crates/relay/src/db/queries.rs` or a new `routes/uniqueness.rs`):
- `email_taken(db: &SqlitePool, email: &str) -> Result<bool, sqlx::Error>`
- `handle_taken(db: &SqlitePool, handle: &str) -> Result<bool, sqlx::Error>`

**Impact:** Single source of truth for cross-table uniqueness logic. Adding a third table to check requires one change, not two.

## P4: Platform Enum

**Problem:** Platform validation is string-based via `is_valid_platform()` match. Invalid platforms only caught at runtime.

**Locations:**
- `register_device.rs:104-106` (definition)
- `create_mobile_account.rs:26,53` (import + call)

**Solution:** Replace with serde-deserializable enum:
```rust
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Platform {
    Ios, Android, Macos, Linux, Windows,
}
```

Deserialization rejects invalid platforms before handler code runs.

**Impact:** Moves validation to the type system. Eliminates `is_valid_platform()` function entirely.

## P5: base32 Helper in Crypto

**Problem:** Identical 5-line base32 encoding setup duplicated in `plc.rs`.

**Locations:**
- `crates/crypto/src/plc.rs:219-224` (build)
- `crates/crypto/src/plc.rs:333-338` (verify)

**Solution:** Extract `fn base32_lowercase() -> Result<Encoding, CryptoError>`.

**Impact:** Trivial, but eliminates the only DRY violation in the crypto crate.

## P6: Break Up `create_did` Handler

**Problem:** Single 270-line function with 13 numbered steps handling auth, validation, external HTTP, and multi-table transaction.

**Location:** `crates/relay/src/routes/create_did.rs:76-345`

**Solution:** Extract phases into named functions:
- `load_pending_account()` — DB lookup
- `validate_genesis_op()` — payload verification
- `post_to_plc_if_needed()` — external HTTP call
- `promote_account()` — transaction: move pending → accounts, issue session

**Impact:** Each phase becomes independently testable. Handler reads like a recipe.

## P7: Clean AC References in Crypto Tests

**Problem:** Per project convention, no ticket/AC references in source code. `crates/crypto/src/shamir.rs` still has AC-prefixed section comments.

**Location:** `crates/crypto/src/shamir.rs:171,191,255`

**Solution:** Reword to describe behavior, not acceptance criteria.

**Impact:** Style-only.

## Implementation Order

| Step | Priority | Effort | Status |
|------|----------|--------|--------|
| 1. Token module | P1 | ~2hr | Done |
| 2. Constraint classification | P2 | ~1hr | Done |
| 3. Uniqueness query helpers | P3 | ~1hr | Done |
| 4. Platform enum | P4 | ~1hr | Done |
| 5. base32 helper | P5 | ~15min | Done |
| 6. Break up create_did | P6 | ~2hr | Done |
| 7. Clean AC references | P7 | ~15min | Done |
