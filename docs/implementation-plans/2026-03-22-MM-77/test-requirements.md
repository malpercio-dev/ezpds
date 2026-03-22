# MM-77 Test Requirements

Maps every acceptance criterion from the MM-77 design plan to either an automated test
or a human-verification step. Organized for use by a test-analyst agent during execution
validation.

**Design plan:** `docs/design-plans/2026-03-22-MM-77.md`
**Implementation plans:** `docs/implementation-plans/2026-03-22-MM-77/phase_01.md` through `phase_06.md`

---

## Summary

| AC Group | Total | Automated | Human-verified |
|----------|-------|-----------|----------------|
| AC1      | 8     | 8         | 0              |
| AC2      | 6     | 6         | 0              |
| AC3      | 5     | 5         | 0              |
| AC4      | 5     | 5         | 0              |
| AC5      | 4     | 4         | 0              |
| AC6      | 3     | 2         | 1              |
| **Total**| **31**| **30**    | **1**          |

Note: The design plan lists 26 numbered sub-criteria (AC1.1-AC1.8, AC2.1-AC2.6,
AC3.1-AC3.5, AC4.1-AC4.5, AC5.1-AC5.4, AC6.1-AC6.3). However, several test functions
cover multiple criteria simultaneously, and some criteria are covered at multiple layers
(unit + integration). The table above counts distinct criteria; the sections below show
every mapping.

---

## Automated Tests

### MM-77.AC1: Authorization code exchange

| Criterion | Description | Type | File | Test Function | Phase |
|-----------|-------------|------|------|---------------|-------|
| AC1.1 | Valid code + code_verifier + DPoP proof with nonce returns 200 with access_token, token_type="DPoP", expires_in=300, refresh_token, scope | Integration | `crates/relay/src/routes/oauth_token.rs` | `tests::authorization_code_happy_path_returns_200_with_tokens` | 5 |
| AC1.2 | Access token is ES256 JWT with typ=at+jwt, cnf.jkt, exp=now+300s | Integration | `crates/relay/src/routes/oauth_token.rs` | `tests::authorization_code_happy_path_returns_200_with_tokens` (asserts `header["typ"] == "at+jwt"`, `header["alg"] == "ES256"`, `payload["cnf"]["jkt"]`) | 5 |
| AC1.3 | Refresh token plaintext is 43-char base64url; stored row has scope='com.atproto.refresh' | Integration + Unit | `crates/relay/src/routes/oauth_token.rs` | `tests::authorization_code_happy_path_returns_200_with_tokens` (asserts `rt.len() == 43`) | 5 |
| AC1.3 (scope) | Stored refresh token row has scope='com.atproto.refresh' | Unit | `crates/relay/src/db/oauth.rs` | `tests::store_oauth_refresh_token_persists_row` (asserts `scope == "com.atproto.refresh"`) | 5 |
| AC1.4 | Invalid code_verifier returns 400 invalid_grant | Integration | `crates/relay/src/routes/oauth_token.rs` | `tests::wrong_code_verifier_returns_invalid_grant` | 5 |
| AC1.5 | Expired auth code (>60s) returns 400 invalid_grant | Unit | `crates/relay/src/db/oauth.rs` | `tests::consume_authorization_code_returns_none_for_expired_code` | 5 |
| AC1.6 | Already-consumed code returns 400 invalid_grant | Integration + Unit | `crates/relay/src/routes/oauth_token.rs` | `tests::consumed_code_returns_invalid_grant` | 5 |
| AC1.6 (db layer) | Second consume returns None | Unit | `crates/relay/src/db/oauth.rs` | `tests::consume_authorization_code_returns_row_and_deletes_it` (second consume asserts `is_none`) | 5 |
| AC1.7 | client_id mismatch returns 400 invalid_grant | Integration | `crates/relay/src/routes/oauth_token.rs` | `tests::client_id_mismatch_returns_invalid_grant` | 5 |
| AC1.8 | redirect_uri mismatch returns 400 invalid_grant | Integration | `crates/relay/src/routes/oauth_token.rs` | `tests::redirect_uri_mismatch_returns_invalid_grant` | 5 |

### MM-77.AC2: DPoP proof validation

| Criterion | Description | Type | File | Test Function | Phase |
|-----------|-------------|------|------|---------------|-------|
| AC2.1 | Valid DPoP proof (ES256, correct htm=POST, htu, fresh iat, non-empty jti) accepted | Integration | `crates/relay/src/routes/oauth_token.rs` | `tests::authorization_code_happy_path_returns_200_with_tokens` (full request with valid DPoP succeeds) | 5 |
| AC2.2 | Access token cnf.jkt matches the DPoP proof's JWK thumbprint | Integration | `crates/relay/src/routes/oauth_token.rs` | `tests::authorization_code_happy_path_returns_200_with_tokens` (asserts `cnf_jkt == expected_jkt`) | 5 |
| AC2.3 | Missing DPoP header returns 400 invalid_dpop_proof | Integration | `crates/relay/src/routes/oauth_token.rs` | `tests::missing_dpop_header_returns_invalid_dpop_proof` | 5 |
| AC2.4 | Wrong htm returns 400 invalid_dpop_proof | Integration | `crates/relay/src/routes/oauth_token.rs` | `tests::dpop_wrong_htm_returns_invalid_dpop_proof` | 5 |
| AC2.5 | Wrong htu returns 400 invalid_dpop_proof | Integration | `crates/relay/src/routes/oauth_token.rs` | `tests::dpop_wrong_htu_returns_invalid_dpop_proof` | 5 |
| AC2.6 | Stale iat (>60s) returns 400 invalid_dpop_proof | Integration | `crates/relay/src/routes/oauth_token.rs` | `tests::dpop_stale_iat_returns_invalid_dpop_proof` | 5 |

### MM-77.AC3: DPoP server nonces

| Criterion | Description | Type | File | Test Function | Phase |
|-----------|-------------|------|------|---------------|-------|
| AC3.1 | Request with valid unexpired nonce accepted | Unit | `crates/relay/src/auth/mod.rs` | `tests::issued_nonce_validates_once` | 3 |
| AC3.2 | No nonce claim in DPoP proof returns 400 use_dpop_nonce + DPoP-Nonce header | Integration | `crates/relay/src/routes/oauth_token.rs` | `tests::dpop_without_nonce_returns_use_dpop_nonce_with_header` | 5 |
| AC3.3 | Expired nonce returns 400 use_dpop_nonce + fresh DPoP-Nonce header | Unit | `crates/relay/src/auth/mod.rs` | `tests::expired_nonce_is_rejected` | 3 |
| AC3.4 | Unknown/fabricated nonce returns 400 use_dpop_nonce | Unit + Integration | `crates/relay/src/auth/mod.rs` | `tests::unknown_nonce_is_rejected` | 3 |
| AC3.4 (integration) | Unknown nonce via HTTP returns use_dpop_nonce | Integration | `crates/relay/src/routes/oauth_token.rs` | `tests::dpop_with_unknown_nonce_returns_use_dpop_nonce` | 5 |
| AC3.5 | Successful token response includes DPoP-Nonce header with fresh nonce | Integration | `crates/relay/src/routes/oauth_token.rs` | `tests::authorization_code_happy_path_returns_200_with_tokens` (asserts `resp.headers().contains_key("DPoP-Nonce")`) | 5 |
| AC3.5 (refresh) | Successful refresh response includes DPoP-Nonce header | Integration | `crates/relay/src/routes/oauth_token.rs` | `tests::refresh_token_happy_path_returns_200_with_new_tokens` (asserts `resp.headers().contains_key("DPoP-Nonce")`) | 6 |

### MM-77.AC4: Refresh token rotation

| Criterion | Description | Type | File | Test Function | Phase |
|-----------|-------------|------|------|---------------|-------|
| AC4.1 | Valid refresh token + DPoP proof returns 200 with new access_token and new refresh_token | Integration | `crates/relay/src/routes/oauth_token.rs` | `tests::refresh_token_happy_path_returns_200_with_new_tokens` | 6 |
| AC4.2 | Old refresh token deleted; second use returns 400 invalid_grant | Integration + Unit | `crates/relay/src/routes/oauth_token.rs` | `tests::refresh_token_second_use_returns_invalid_grant` | 6 |
| AC4.2 (db layer) | Second consume returns None | Unit | `crates/relay/src/db/oauth.rs` | `tests::consume_oauth_refresh_token_returns_row_and_deletes_it` | 6 |
| AC4.3 | Expired refresh token (>24h) returns 400 invalid_grant | Integration + Unit | `crates/relay/src/routes/oauth_token.rs` | `tests::refresh_token_expired_returns_invalid_grant` | 6 |
| AC4.3 (db layer) | Expired token returns None from consume | Unit | `crates/relay/src/db/oauth.rs` | `tests::consume_oauth_refresh_token_returns_none_for_expired_token` | 6 |
| AC4.4 | DPoP key thumbprint mismatch returns 400 invalid_grant | Integration | `crates/relay/src/routes/oauth_token.rs` | `tests::refresh_token_jkt_mismatch_returns_invalid_grant` | 6 |
| AC4.5 | client_id mismatch on refresh returns 400 invalid_grant | Integration | `crates/relay/src/routes/oauth_token.rs` | `tests::refresh_token_client_id_mismatch_returns_invalid_grant` | 6 |

### MM-77.AC5: Error response format

| Criterion | Description | Type | File | Test Function | Phase |
|-----------|-------------|------|------|---------------|-------|
| AC5.1 | All errors return JSON with error and error_description string fields | Integration | `crates/relay/src/routes/oauth_token.rs` | `tests::error_response_has_error_and_error_description_fields` | 4 |
| AC5.2 | Unknown grant_type returns 400 unsupported_grant_type | Integration | `crates/relay/src/routes/oauth_token.rs` | `tests::unknown_grant_type_returns_400_unsupported` | 4 |
| AC5.3 | Missing required params returns 400 invalid_request | Integration | `crates/relay/src/routes/oauth_token.rs` | `tests::missing_grant_type_returns_400_invalid_request` | 4 |
| AC5.4 | No HTML in error responses | Integration | `crates/relay/src/routes/oauth_token.rs` | `tests::error_response_content_type_is_json` (asserts content-type is application/json) | 4 |

### MM-77.AC6: OAuth signing key persistence

| Criterion | Description | Type | File | Test Function | Phase |
|-----------|-------------|------|------|---------------|-------|
| AC6.1 | First startup generates P-256 keypair, stores encrypted in oauth_signing_key | Unit | `crates/relay/src/db/oauth.rs` | `tests::store_and_retrieve_oauth_signing_key` | 2 |
| AC6.3 | Access tokens use ES256 signing, not HS256 | Integration | `crates/relay/src/routes/oauth_token.rs` | `tests::authorization_code_happy_path_returns_200_with_tokens` (asserts `header["alg"] == "ES256"`) | 5 |

---

## Human Verification

### MM-77.AC6.2: Subsequent restarts reload the same key (same kid in JWTs)

**Why it cannot be automated in the existing test suite:** This criterion requires
restarting the relay binary and verifying that access tokens issued before and after
the restart carry the same `kid` in their JWT header. The test suite uses ephemeral
in-memory SQLite databases and a fresh `test_state()` per test. There is no mechanism
within `cargo test` to simulate a process restart with persistent state across
invocations.

**Verification approach:**

1. Start the relay binary with `signing_key_master_key` configured and a persistent
   SQLite database path.
2. Issue an authorization code exchange request (via Bruno or curl). Record the `kid`
   from the access token JWT header.
3. Stop the relay process.
4. Restart the relay with the same configuration and database.
5. Issue another authorization code exchange request. Record the `kid`.
6. Verify that both `kid` values are identical.

**Partial automated coverage:** The DB round-trip is covered by
`tests::store_and_retrieve_oauth_signing_key` (Phase 2), which confirms that a stored
key can be read back with the same `id`. The `load_or_create_oauth_signing_key` function
in `auth/mod.rs` is the code path that loads the existing key on restart -- its
correctness is validated by the DB test, but the full restart cycle (including `main.rs`
startup flow) requires a running binary.

---

## Additional Unit Tests (infrastructure)

These tests do not map to a specific acceptance criterion but are required for
infrastructure correctness and are specified in the implementation plan.

| Test | Type | File | Test Function | Phase |
|------|------|------|---------------|-------|
| V012 migration applies without error | Smoke | All existing test files (migration runner runs on every test_pool) | (implicit -- all tests pass) | 1 |
| OAuth signing key DB returns None when empty | Unit | `crates/relay/src/db/oauth.rs` | `tests::get_oauth_signing_key_returns_none_when_empty` | 2 |
| Nonce is consumed after single use | Unit | `crates/relay/src/auth/mod.rs` | `tests::issued_nonce_validates_once` (second validation fails) | 3 |
| Cleanup removes only expired nonces | Unit | `crates/relay/src/auth/mod.rs` | `tests::cleanup_removes_only_expired_nonces` | 3 |
| Nonce format is 22-char base64url | Unit | `crates/relay/src/auth/mod.rs` | `tests::issued_nonce_is_22_chars_base64url` | 3 |
| GET /oauth/token returns 405 | Integration | `crates/relay/src/routes/oauth_token.rs` | `tests::get_token_endpoint_returns_405` | 4 |
| consume_authorization_code returns None for unknown code | Unit | `crates/relay/src/db/oauth.rs` | `tests::consume_authorization_code_returns_none_for_unknown_code` | 5 |
| consume_oauth_refresh_token returns None for unknown token | Unit | `crates/relay/src/db/oauth.rs` | `tests::consume_oauth_refresh_token_returns_none_for_unknown_token` | 6 |

---

## Test Execution Commands

Run all tests for the relay crate:
```
cargo test -p relay
```

Run only token endpoint tests:
```
cargo test -p relay routes::oauth_token
```

Run only DB-layer OAuth tests:
```
cargo test -p relay db::oauth
```

Run only auth module tests (nonce store):
```
cargo test -p relay auth::tests
```

Run clippy (warnings-as-errors):
```
cargo clippy --workspace -- -D warnings
```

Run format check:
```
cargo fmt --all --check
```
