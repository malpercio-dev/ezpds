# MM-90: Test Requirements

This document maps every MM-90 acceptance criterion to either an automated test or a documented human verification step. It is derived from the design plan (`docs/design-plans/2026-03-13-MM-90.md`) and the implementation phases (`phase_01.md`, `phase_02.md`).

All automated tests use Rust's built-in `#[test]` / `#[tokio::test]` framework. Crypto-crate tests are pure unit tests (no I/O). Relay-crate tests are integration tests that spin up an in-memory SQLite database, a wiremock HTTP server (for plc.directory), and exercise the full axum handler via `tower::ServiceExt::oneshot`.

---

## Automated Test Map

### MM-90.AC1: `verify_genesis_op` in the crypto crate

| Criterion | Description | Test Type | File Path | Test Function |
|-----------|-------------|-----------|-----------|---------------|
| MM-90.AC1.1 | Valid signed genesis op returns `VerifiedGenesisOp` with correct `did`, `also_known_as`, `verification_methods`, and `atproto_pds_endpoint` | Unit | `crates/crypto/src/plc.rs` (`mod tests`) | `verify_valid_op_returns_correct_fields` |
| MM-90.AC1.2 | DID from `verify_genesis_op` matches DID from `build_did_plc_genesis_op` (round-trip CBOR consistency) | Unit | `crates/crypto/src/plc.rs` (`mod tests`) | `verify_did_matches_build_did_plc_genesis_op` |
| MM-90.AC1.3 | Op verified against a different rotation key returns `CryptoError::PlcOperation` | Unit | `crates/crypto/src/plc.rs` (`mod tests`) | `verify_wrong_rotation_key_returns_error` |
| MM-90.AC1.4 | Op with a corrupted signature (one byte flipped) returns `CryptoError::PlcOperation` | Unit | `crates/crypto/src/plc.rs` (`mod tests`) | `verify_corrupted_signature_returns_error` |
| MM-90.AC1.5 | Op JSON with unknown/extra fields is rejected with `CryptoError::PlcOperation` | Unit | `crates/crypto/src/plc.rs` (`mod tests`) | `verify_unknown_fields_returns_error` |

**Implementation notes:**

- Tests use `make_op_for_verify()`, a helper that calls `generate_p256_keypair` and `build_did_plc_genesis_op` to produce a valid signed op and the corresponding key URI. The helper uses the same keypair for both signing and rotation so that `verify_genesis_op` can be called with `signing_kp.key_id` (the key that actually signed the op).
- AC1.5 relies on `#[serde(deny_unknown_fields)]` on `SignedPlcOp`. The test injects an `"unknownField"` key into the JSON before calling `verify_genesis_op`.
- AC1.2 confirms byte-level CBOR encoding consistency between the build and verify paths; both must produce the same DID from the same inputs. This is critical because any CBOR divergence would break real-world interop with plc.directory.

### MM-90.AC2: `POST /v1/dids` -- happy path and account promotion

| Criterion | Description | Test Type | File Path | Test Function |
|-----------|-------------|-----------|-----------|---------------|
| MM-90.AC2.1 | Valid request returns `200 OK` with `{ "did": "did:plc:...", "did_document": {...}, "status": "active" }` | Integration | `crates/relay/src/routes/create_did.rs` (`mod tests`) | `happy_path_promotes_account_and_returns_did` |
| MM-90.AC2.2 | After success, `accounts` row exists with correct `did` and `email`; `password_hash` is NULL | Integration | `crates/relay/src/routes/create_did.rs` (`mod tests`) | `happy_path_promotes_account_and_returns_did` |
| MM-90.AC2.3 | After success, `did_documents` row exists with non-empty `document` JSON | Integration | `crates/relay/src/routes/create_did.rs` (`mod tests`) | `happy_path_promotes_account_and_returns_did` |
| MM-90.AC2.4 | After success, `handles` row links the pending account's handle to the DID | Integration | `crates/relay/src/routes/create_did.rs` (`mod tests`) | `happy_path_promotes_account_and_returns_did` |
| MM-90.AC2.5 | After success, `pending_accounts` and `pending_sessions` rows are deleted | Integration | `crates/relay/src/routes/create_did.rs` (`mod tests`) | `happy_path_promotes_account_and_returns_did` |
| MM-90.AC2.6 | When `pending_did` is already set (retry), plc.directory is not called; promotion completes with 200 | Integration | `crates/relay/src/routes/create_did.rs` (`mod tests`) | `retry_with_pending_did_skips_plc_directory` |

**Implementation notes:**

- AC2.1 through AC2.5 are all verified within the single `happy_path_promotes_account_and_returns_did` test. This is deliberate: the happy path is a single atomic flow, and splitting these into separate tests would duplicate all the setup (keypair generation, pending account insertion, wiremock plc.directory mock, request dispatch) without meaningful isolation benefit. Each AC is verified by a distinct assertion block within the test, annotated with its criterion ID in a comment.
- AC2.6 uses wiremock's `expect(0)` to assert that plc.directory receives zero requests. The test pre-stores `pending_did` in the database before dispatching the request, simulating a retry after a partial failure.
- The `insert_test_data` helper creates a full prerequisite chain: claim_code, pending_account, device, and pending_session. No relay signing key is needed for MM-90 (unlike MM-89).
- The `make_signed_op` helper generates a fresh P-256 keypair and calls `build_did_plc_genesis_op` with the same key for both rotation and signing, producing a valid signed op that `verify_genesis_op` will accept.
- `test_state_for_did` wraps `test_state_with_plc_url` (from `crates/relay/src/app.rs`) with the mock server URL. No `signing_key_master_key` parameter is needed for MM-90.

### MM-90.AC3: `POST /v1/dids` -- failure cases

| Criterion | Description | Test Type | File Path | Test Function |
|-----------|-------------|-----------|-----------|---------------|
| MM-90.AC3.1 | Invalid ECDSA signature returns 400 `INVALID_CLAIM` | Integration | `crates/relay/src/routes/create_did.rs` (`mod tests`) | `invalid_signature_returns_400` |
| MM-90.AC3.2 | `alsoKnownAs[0]` mismatch with `pending_accounts.handle` returns 400 `INVALID_CLAIM` | Integration | `crates/relay/src/routes/create_did.rs` (`mod tests`) | `wrong_handle_in_op_returns_400` |
| MM-90.AC3.3 | `services.atproto_pds.endpoint` mismatch with `config.public_url` returns 400 `INVALID_CLAIM` | Integration | `crates/relay/src/routes/create_did.rs` (`mod tests`) | `wrong_service_endpoint_returns_400` |
| MM-90.AC3.4 | `rotationKeys[0]` mismatch with request body `rotationKeyPublic` returns 400 `INVALID_CLAIM` | Integration | `crates/relay/src/routes/create_did.rs` (`mod tests`) | `wrong_rotation_key_in_op_returns_400` |
| MM-90.AC3.5 | Already-promoted account (existing `accounts` row for DID) returns 409 `DID_ALREADY_EXISTS` | Integration | `crates/relay/src/routes/create_did.rs` (`mod tests`) | `already_promoted_account_returns_409` |
| MM-90.AC3.6 | Missing or expired `pending_session` token returns 401 `UNAUTHORIZED` | Integration | `crates/relay/src/routes/create_did.rs` (`mod tests`) | `missing_auth_returns_401` |
| MM-90.AC3.7 | plc.directory returns non-2xx returns 502 `PLC_DIRECTORY_ERROR` | Integration | `crates/relay/src/routes/create_did.rs` (`mod tests`) | `plc_directory_error_returns_502` |

**Implementation notes:**

- AC3.1 corrupts the signature by base64url-decoding, flipping one byte (`sig_bytes[0] ^= 0xff`), and re-encoding. This ensures the handler's call to `crypto::verify_genesis_op` fails with a signature verification error, which the handler maps to 400 `INVALID_CLAIM`.
- AC3.2 builds a signed op with `"different.handle.com"` but the pending_account row has `setup.handle`. The op passes crypto verification (valid signature), but fails semantic validation at step 6.
- AC3.3 builds a signed op with `"https://wrong.example.com"` as the PDS endpoint, while the server's `config.public_url` is `"https://test.example.com"`.
- AC3.4 uses two distinct keypairs (`kp_x` for signing, `kp_y` for the `rotationKeys[0]` field in the op). The request body sends `kp_x.key_id` as `rotationKeyPublic`. Crypto verification passes (signed by `kp_x`, verified against `kp_x`), but `rotation_keys[0]` is `kp_y` which does not match the request's `rotationKeyPublic`. This isolates the semantic check from the cryptographic check.
- AC3.5 pre-inserts an `accounts` row with the same DID before dispatching the request. The handler detects the existing row at step 8 and returns 409.
- AC3.6 sends a request with no `Authorization` header. The `require_pending_session` auth helper returns 401 before any handler logic executes.
- AC3.7 configures wiremock to return HTTP 500. The handler receives the non-2xx response at step 9 and returns 502 `PLC_DIRECTORY_ERROR`.

### MM-90.AC4: DID document correctness

| Criterion | Description | Test Type | File Path | Test Function |
|-----------|-------------|-----------|-----------|---------------|
| MM-90.AC4.1 | `did_document` contains `verificationMethod` with `publicKeyMultibase` derived from `verificationMethods.atproto` | Integration | `crates/relay/src/routes/create_did.rs` (`mod tests`) | `happy_path_promotes_account_and_returns_did` |
| MM-90.AC4.2 | `did_document` contains `alsoKnownAs` with `at://` + account handle | Integration | `crates/relay/src/routes/create_did.rs` (`mod tests`) | `happy_path_promotes_account_and_returns_did` |
| MM-90.AC4.3 | `did_document` contains service entry with `serviceEndpoint` matching `config.public_url` | Integration | `crates/relay/src/routes/create_did.rs` (`mod tests`) | `happy_path_promotes_account_and_returns_did` |

**Implementation notes:**

- AC4.1 through AC4.3 are verified within `happy_path_promotes_account_and_returns_did` by inspecting the `did_document` JSON in the response body.
- AC4.1 asserts that `verificationMethod[0].publicKeyMultibase` starts with `"z"` (multibase-encoded compressed P-256 key). The `build_did_document` function strips the `did:key:` prefix from `verificationMethods["atproto"]` to produce the multibase value.
- AC4.2 asserts that `alsoKnownAs` contains `"at://{handle}"`, matching the value from the pending account.
- AC4.3 asserts that `service[0].serviceEndpoint` equals `"https://test.example.com"` (the test `config.public_url`).

---

## Human Verification Steps

All 19 acceptance criteria are covered by automated tests. No criteria require manual human verification.

The Bruno API collection file (`bruno/create-did.bru`) is updated as part of Phase 2 Task 2, but this is developer tooling and is not mapped to any acceptance criterion. Its correctness can be visually confirmed by opening it in the Bruno desktop app and inspecting the request body shape.

---

## Summary

| Category | Count |
|----------|-------|
| Total acceptance criteria | 19 |
| Automated tests (unit) | 5 |
| Automated tests (integration) | 14 |
| Human verification required | 0 |
| Distinct test functions | 14 |

**Breakdown by test function:**

| # | Test Function | Criteria Covered | Crate | Type |
|---|---------------|-----------------|-------|------|
| 1 | `verify_valid_op_returns_correct_fields` | AC1.1 | crypto | Unit |
| 2 | `verify_did_matches_build_did_plc_genesis_op` | AC1.2 | crypto | Unit |
| 3 | `verify_wrong_rotation_key_returns_error` | AC1.3 | crypto | Unit |
| 4 | `verify_corrupted_signature_returns_error` | AC1.4 | crypto | Unit |
| 5 | `verify_unknown_fields_returns_error` | AC1.5 | crypto | Unit |
| 6 | `happy_path_promotes_account_and_returns_did` | AC2.1, AC2.2, AC2.3, AC2.4, AC2.5, AC4.1, AC4.2, AC4.3 | relay | Integration |
| 7 | `retry_with_pending_did_skips_plc_directory` | AC2.6 | relay | Integration |
| 8 | `invalid_signature_returns_400` | AC3.1 | relay | Integration |
| 9 | `wrong_handle_in_op_returns_400` | AC3.2 | relay | Integration |
| 10 | `wrong_service_endpoint_returns_400` | AC3.3 | relay | Integration |
| 11 | `wrong_rotation_key_in_op_returns_400` | AC3.4 | relay | Integration |
| 12 | `already_promoted_account_returns_409` | AC3.5 | relay | Integration |
| 13 | `missing_auth_returns_401` | AC3.6 | relay | Integration |
| 14 | `plc_directory_error_returns_502` | AC3.7 | relay | Integration |
