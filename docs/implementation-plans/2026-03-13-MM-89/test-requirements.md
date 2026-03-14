# Test Requirements — MM-89

## Overview
MM-89 implements did:plc DID creation and account promotion for the ezpds relay. The `crypto` crate gains a pure function (`build_did_plc_genesis_op`) that constructs a signed did:plc genesis operation and derives the resulting DID from key material and identity fields. The `relay` crate gains a `POST /v1/dids` endpoint that authenticates a pending session, calls the crypto function, submits the signed operation to the external PLC Directory, and atomically promotes the pending account to an active account in the database.

## Automated Tests

| Criterion | Description | Test Type | Expected Test File | Task |
|-----------|-------------|-----------|-------------------|------|
| MM-89.AC1.1 | `build_did_plc_genesis_op` with valid inputs returns `PlcGenesisOp` with `did` matching `^did:plc:[a-z2-7]{24}$` | unit | `crates/crypto/src/plc.rs` (inline `#[cfg(test)]`) | Phase 1, Task 2 |
| MM-89.AC1.2 | `signed_op_json` contains all required fields: `type`, `rotationKeys`, `verificationMethods`, `alsoKnownAs`, `services`, `prev` (null), `sig` | unit | `crates/crypto/src/plc.rs` (inline `#[cfg(test)]`) | Phase 1, Task 2 |
| MM-89.AC1.3 | `rotation_key` appears as `rotationKeys[0]`; `signing_key` appears as both `rotationKeys[1]` and `verificationMethods.atproto` | unit | `crates/crypto/src/plc.rs` (inline `#[cfg(test)]`) | Phase 1, Task 2 |
| MM-89.AC1.4 | Calling `build_did_plc_genesis_op` twice with identical inputs returns the same `did` (RFC 6979 determinism) | unit | `crates/crypto/src/plc.rs` (inline `#[cfg(test)]`) | Phase 1, Task 2 |
| MM-89.AC1.5 | Invalid `signing_private_key` bytes (zero scalar) returns `CryptoError::PlcOperation` | unit | `crates/crypto/src/plc.rs` (inline `#[cfg(test)]`) | Phase 1, Task 2 |
| MM-89.AC2.1 | Valid request with a live `pending_session` token returns `200 OK` with `{ "did": "did:plc:...", "status": "active" }` | integration | `crates/relay/src/routes/create_did.rs` (inline `#[cfg(test)]`) | Phase 2, Task 6 |
| MM-89.AC2.2 | After success, `accounts` row exists with `did` as PK, correct `email`, and `password_hash` NULL | integration | `crates/relay/src/routes/create_did.rs` (inline `#[cfg(test)]`) | Phase 2, Task 6 |
| MM-89.AC2.3 | After success, `did_documents` row exists for the DID with non-empty `document` JSON | integration | `crates/relay/src/routes/create_did.rs` (inline `#[cfg(test)]`) | Phase 2, Task 6 |
| MM-89.AC2.4 | After success, `handles` row exists linking the handle to the DID | integration | `crates/relay/src/routes/create_did.rs` (inline `#[cfg(test)]`) | Phase 2, Task 6 |
| MM-89.AC2.5 | After success, `pending_accounts` and `pending_sessions` rows for the account are deleted | integration | `crates/relay/src/routes/create_did.rs` (inline `#[cfg(test)]`) | Phase 2, Task 6 |
| MM-89.AC2.6 | When `pending_did` is already set (client retry), handler skips the plc.directory HTTP call and completes DB promotion, returning 200 | integration | `crates/relay/src/routes/create_did.rs` (inline `#[cfg(test)]`) | Phase 2, Task 6 |
| MM-89.AC2.7 | Missing `Authorization` header returns 401 `UNAUTHORIZED` | integration | `crates/relay/src/routes/create_did.rs` (inline `#[cfg(test)]`) | Phase 2, Task 6 |
| MM-89.AC2.8 | Expired `pending_session` token returns 401 `UNAUTHORIZED` | integration | `crates/relay/src/routes/create_did.rs` (inline `#[cfg(test)]`) | Phase 2, Task 6 |
| MM-89.AC2.9 | `signingKey` not present in `relay_signing_keys` returns 404 `NOT_FOUND` | integration | `crates/relay/src/routes/create_did.rs` (inline `#[cfg(test)]`) | Phase 2, Task 6 |
| MM-89.AC2.10 | Account already fully promoted (`accounts` row already exists) returns 409 `DID_ALREADY_EXISTS` | integration | `crates/relay/src/routes/create_did.rs` (inline `#[cfg(test)]`) | Phase 2, Task 6 |
| MM-89.AC2.11 | plc.directory returns non-2xx returns 502 `PLC_DIRECTORY_ERROR` | integration | `crates/relay/src/routes/create_did.rs` (inline `#[cfg(test)]`) | Phase 2, Task 6 |
| MM-89.AC3.1 | V008 migration applies cleanly on top of V007; `accounts.password_hash` accepts NULL; `pending_accounts.pending_did` column exists | integration | `crates/relay/src/routes/create_did.rs` (inline `#[cfg(test)]`) | Phase 2, Task 6 |
| MM-89.AC3.2 | `sig` field in `signed_op_json` is a base64url string (no padding) decoding to exactly 64 bytes | unit | `crates/crypto/src/plc.rs` (inline `#[cfg(test)]`) | Phase 1, Task 2 |
| MM-89.AC3.3 | `alsoKnownAs` in `signed_op_json` contains `at://{handle}` (not bare handle) | unit | `crates/crypto/src/plc.rs` (inline `#[cfg(test)]`) | Phase 1, Task 2 |

## Human Verification Required

| Criterion | Description | Why Automated Testing Is Insufficient | Verification Approach |
|-----------|-------------|---------------------------------------|----------------------|

No criteria require human verification. All 19 acceptance criteria are covered by automated tests. The integration tests in Phase 2 use `wiremock` to simulate plc.directory responses, which is sufficient to verify the relay's behavior without requiring a live external service. The V008 migration (AC3.1) is implicitly verified by every integration test in Phase 2, since `test_state_for_did` calls `run_migrations` on an in-memory SQLite database (applying V001 through V008), and the happy-path test (AC2.1/AC2.2) inserts an `accounts` row with `password_hash = NULL` and reads back `pending_did` from `pending_accounts`, exercising both schema changes.

## Coverage Summary
- Total criteria: 19
- Automated: 19
- Human verification: 0
- Coverage: 100%
