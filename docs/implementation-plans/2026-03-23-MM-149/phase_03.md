# MM-149 OAuth PKCE Client Implementation Plan

**Goal:** Implement the DPoP keypair type (Keychain-persisted P-256 key) and the manual JOSE proof builder, plus Keychain helpers for OAuth tokens.

**Architecture:** `DPoPKeypair` wraps a P-256 `SigningKey`. Proofs are constructed manually — base64url-encode header JSON + claims JSON, sign the `header.payload` signing input with P-256/SHA-256, base64url-encode the raw R||S signature. No JWT library needed. The relay's validator in `crates/relay/src/auth/dpop.rs` defines exactly what the proof must contain. The Keychain helpers in `keychain.rs` follow the existing `store_item`/`get_item` pattern.

**Tech Stack:** `p256 = "0.13"` (ecdsa + pkcs8 features), `sha2 = "0.10"`, `base64 = "0.21"` (URL_SAFE_NO_PAD), `uuid = "1"` (v4)

**Scope:** 7 phases from original design (phase 3 of 7)

**Codebase verified:** 2026-03-23

---

## Acceptance Criteria Coverage

This phase implements and tests:

### MM-149.AC3: DPoP proofs are correctly formed
- **MM-149.AC3.1 Success:** DPoP proof header contains `typ: "dpop+jwt"`, `alg: "ES256"`, and a valid P-256 `jwk`
- **MM-149.AC3.2 Success:** DPoP proof payload contains `jti`, `htm`, `htu`, `iat`
- **MM-149.AC3.3 Success:** `ath` claim present and equals `base64url(sha256(access_token))` on resource requests
- **MM-149.AC3.4 Success:** `nonce` claim present when a server nonce has been provided
- **MM-149.AC3.5 Success:** Proof signature verifies against the `jwk` embedded in the header

---

<!-- START_SUBCOMPONENT_A (tasks 1-2) -->

<!-- START_TASK_1 -->
### Task 1: Add sha2, base64, uuid dependencies to identity-wallet Cargo.toml

**Verifies:** None (infrastructure)

**Files:**
- Modify: `apps/identity-wallet/src-tauri/Cargo.toml`

These crates are already in workspace dependencies (root `Cargo.toml` lines 65, 68, 71) but are not yet declared in identity-wallet.

**Step 1: Add to `[dependencies]`**

Add after the existing `serde_json = { workspace = true }` line:

```toml
sha2 = { workspace = true }
base64 = { workspace = true }
uuid = { workspace = true }
```

The `uuid` workspace dep already has `features = ["v4"]` so no extra features spec needed.

**Step 2: Build to verify**

```bash
cargo build -p identity-wallet
```

Expected: builds without errors.

<!-- END_TASK_1 -->

<!-- START_TASK_2 -->
### Task 2: Add OAuth Keychain helpers to keychain.rs

**Verifies:** None (helpers used by Phase 5; no AC directly)

**Files:**
- Modify: `apps/identity-wallet/src-tauri/src/keychain.rs`

Add four helpers at the end of the file, following the same pattern as any existing helpers. The account keys match the design plan constants and follow the same `"ezpds-identity-wallet"` service (already enforced by the `SERVICE` constant in the file).

**Step 1: Read the bottom of `apps/identity-wallet/src-tauri/src/keychain.rs`**

Find where the existing helpers and constants are defined (the public `store_item`/`get_item`/`delete_item` API plus the `SERVICE` constant).

**Step 2: Add the four OAuth Keychain helpers**

Add at the end of the file (before any `#[cfg(test)]` block if one exists):

```rust
// ── OAuth Keychain helpers ─────────────────────────────────────────────────────

const DPOP_KEY_PRIV_ACCOUNT: &str = "oauth-dpop-key-priv";
const OAUTH_ACCESS_TOKEN_ACCOUNT: &str = "oauth-access-token";
const OAUTH_REFRESH_TOKEN_ACCOUNT: &str = "oauth-refresh-token";

/// Store the DPoP private key scalar (32 bytes) in the Keychain.
pub fn store_dpop_key(private_bytes: &[u8]) -> Result<(), KeychainError> {
    store_item(DPOP_KEY_PRIV_ACCOUNT, private_bytes)
}

/// Load the DPoP private key scalar from the Keychain.
///
/// Returns `None` if no key has been stored yet (first run).
pub fn load_dpop_key() -> Option<[u8; 32]> {
    match get_item(DPOP_KEY_PRIV_ACCOUNT) {
        Ok(bytes) if bytes.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            Some(arr)
        }
        Ok(_) => {
            tracing::warn!("DPoP key in Keychain has unexpected length; treating as absent");
            None
        }
        Err(e) if is_not_found(&e) => None,
        Err(e) => {
            tracing::error!(error = ?e, "Keychain error loading DPoP key");
            None
        }
    }
}

/// Store the OAuth access token and refresh token in the Keychain.
pub fn store_oauth_tokens(access_token: &str, refresh_token: &str) -> Result<(), KeychainError> {
    store_item(OAUTH_ACCESS_TOKEN_ACCOUNT, access_token.as_bytes())?;
    store_item(OAUTH_REFRESH_TOKEN_ACCOUNT, refresh_token.as_bytes())?;
    Ok(())
}

/// Load the OAuth access token and refresh token from the Keychain.
///
/// Returns `None` if either token is missing (not yet authenticated).
pub fn load_oauth_tokens() -> Option<(String, String)> {
    let access = match get_item(OAUTH_ACCESS_TOKEN_ACCOUNT) {
        Ok(b) => String::from_utf8(b).ok()?,
        Err(e) if is_not_found(&e) => return None,
        Err(e) => {
            tracing::error!(error = ?e, "Keychain error loading access token");
            return None;
        }
    };
    let refresh = match get_item(OAUTH_REFRESH_TOKEN_ACCOUNT) {
        Ok(b) => String::from_utf8(b).ok()?,
        Err(e) if is_not_found(&e) => return None,
        Err(e) => {
            tracing::error!(error = ?e, "Keychain error loading refresh token");
            return None;
        }
    };
    Some((access, refresh))
}
```

**Step 3: Build to verify**

```bash
cargo build -p identity-wallet
```

Expected: builds without errors. The `tracing` crate is already a dependency.

<!-- END_TASK_2 -->

<!-- END_SUBCOMPONENT_A -->

<!-- START_SUBCOMPONENT_B (tasks 3-5) -->

<!-- START_TASK_3 -->
### Task 3: Implement DPoPKeypair in oauth.rs

**Verifies:** MM-149.AC3.1 (header fields), MM-149.AC3.2 (claims fields), MM-149.AC3.3 (ath), MM-149.AC3.4 (nonce), MM-149.AC3.5 (signature verifies)

**Files:**
- Modify: `apps/identity-wallet/src-tauri/src/oauth.rs`

The DPoP proof format is validated by the relay's `crates/relay/src/auth/dpop.rs` — study that file's expectations when reading the code below. Manual JWT construction: `base64url(header_json)` + `.` + `base64url(claims_json)`, then sign those bytes with P-256/SHA-256, then append `.` + `base64url(raw_RS_signature)`.

**Step 1: Add imports at the top of oauth.rs**

Add these imports to the top of the file, after the existing `use` statements:

```rust
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use p256::ecdsa::{SigningKey, Signature, signature::Signer};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;
```

**Step 2: Define DPoPKeypair and OAuthError**

Add after the existing `AppState` definition:

```rust
// ── OAuth error ───────────────────────────────────────────────────────────────

/// Error type for all OAuth-related operations.
///
/// Variants serialize as `{ "code": "SCREAMING_SNAKE_CASE" }` to match the
/// existing error pattern (`CreateAccountError`, `DeviceKeyError`, etc.).
#[derive(Debug, thiserror::Error, serde::Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", tag = "code")]
pub enum OAuthError {
    #[error("DPoP keypair generation failed")]
    DpopKeyGenFailed,
    #[error("DPoP keypair is invalid")]
    DpopKeyInvalid,
    #[error("DPoP proof construction failed")]
    DpopProofFailed,
    #[error("Keychain error")]
    KeychainError,
    #[error("State mismatch in OAuth callback")]
    StateMismatch,
    #[error("OAuth callback abandoned")]
    CallbackAbandoned,
    #[error("PAR request failed")]
    ParFailed,
    #[error("Token exchange failed")]
    TokenExchangeFailed,
    #[error("Token refresh failed")]
    TokenRefreshFailed,
    #[error("Not authenticated")]
    NotAuthenticated,
}

// ── DPoP keypair ─────────────────────────────────────────────────────────────

/// A P-256 keypair used to produce DPoP proofs.
///
/// The private key scalar (32 bytes) is persisted in the iOS Keychain under
/// `"oauth-dpop-key-priv"`. The same key is used for all DPoP proofs across
/// app sessions — it is never rotated by this implementation.
pub struct DPoPKeypair {
    signing_key: SigningKey,
}

impl DPoPKeypair {
    /// Load the DPoP keypair from Keychain, or generate and persist a new one.
    pub fn get_or_create() -> Result<Self, OAuthError> {
        if let Some(private_bytes) = crate::keychain::load_dpop_key() {
            let signing_key = SigningKey::from_slice(&private_bytes)
                .map_err(|_| OAuthError::DpopKeyInvalid)?;
            return Ok(Self { signing_key });
        }

        // Generate a new P-256 keypair via the shared crypto crate.
        let keypair = crypto::generate_p256_keypair().map_err(|_| OAuthError::DpopKeyGenFailed)?;
        // `private_key_bytes` is `Zeroizing<[u8; 32]>`, which derefs directly to `[u8; 32]`.
        let private_bytes: [u8; 32] = *keypair.private_key_bytes;

        crate::keychain::store_dpop_key(&private_bytes)
            .map_err(|_| OAuthError::KeychainError)?;

        let signing_key = SigningKey::from_slice(&private_bytes)
            .map_err(|_| OAuthError::DpopKeyInvalid)?;
        Ok(Self { signing_key })
    }

    /// Build the public JWK for this keypair (EC, P-256, kty/crv/x/y only — no private fields).
    ///
    /// The relay's validator expects exactly: `{"kty":"EC","crv":"P-256","x":"<b64url>","y":"<b64url>"}`.
    pub fn public_jwk(&self) -> serde_json::Value {
        let verifying_key = self.signing_key.verifying_key();
        let point = verifying_key.to_encoded_point(false); // false = uncompressed: 04 || x || y
        let x = URL_SAFE_NO_PAD.encode(point.x().expect("P-256 uncompressed point has x"));
        let y = URL_SAFE_NO_PAD.encode(point.y().expect("P-256 uncompressed point has y"));
        serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": x,
            "y": y,
        })
    }

    /// Compute the RFC 7638 JWK thumbprint: `base64url(SHA-256(canonical_jwk_json))`.
    ///
    /// The canonical JSON uses lexicographically-sorted keys (crv, kty, x, y) per RFC 7638 §3.2.
    /// This matches the relay's `jwk_thumbprint()` function in `crates/relay/src/auth/dpop.rs`.
    pub fn public_jwk_thumbprint(&self) -> String {
        let jwk = self.public_jwk();
        // Canonical member set per RFC 7638 §3.2 — lexicographic order for EC keys.
        // serde_json internally represents JSON objects as BTreeMap, which serializes
        // keys in lexicographic order. This is what RFC 7638 §3.2 requires for the
        // canonical JSON. The key ordering here (crv < kty < x < y) is lexicographic.
        let canonical = serde_json::json!({
            "crv": jwk["crv"],
            "kty": jwk["kty"],
            "x": jwk["x"],
            "y": jwk["y"],
        });
        let canonical_json = serde_json::to_string(&canonical)
            .expect("canonical JWK serialization is infallible for known types");
        let hash = Sha256::digest(canonical_json.as_bytes());
        URL_SAFE_NO_PAD.encode(hash)
    }

    /// Build a DPoP proof JWT for the given HTTP method, URL, and optional claims.
    ///
    /// - `htm`: HTTP method in uppercase, e.g. `"POST"` or `"GET"`
    /// - `htu`: Full target URL without query string, e.g. `"https://relay.ezpds.com/oauth/token"`
    /// - `nonce`: Server-issued nonce from a prior `use_dpop_nonce` 400 response (if any)
    /// - `ath`: `base64url(SHA-256(access_token_ascii))` — required for resource requests; None for token requests
    ///
    /// Proof format: `base64url(header_json)`.`base64url(claims_json)`.`base64url(sig)`
    /// where sig is the raw 64-byte R||S P-256 ECDSA signature of the signing input.
    pub fn make_proof(
        &self,
        htm: &str,
        htu: &str,
        nonce: Option<&str>,
        ath: Option<&str>,
    ) -> Result<String, OAuthError> {
        let jwk = self.public_jwk();

        // Header JSON.
        let header = serde_json::json!({
            "typ": "dpop+jwt",
            "alg": "ES256",
            "jwk": jwk,
        });
        let header_b64 = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&header).map_err(|_| OAuthError::DpopProofFailed)?,
        );

        // Claims JSON.
        let iat = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| OAuthError::DpopProofFailed)?
            .as_secs() as i64;

        let mut claims = serde_json::json!({
            "jti": Uuid::new_v4().to_string(),
            "htm": htm,
            "htu": htu,
            "iat": iat,
        });

        if let Some(n) = nonce {
            claims["nonce"] = serde_json::Value::String(n.to_string());
        }
        if let Some(a) = ath {
            claims["ath"] = serde_json::Value::String(a.to_string());
        }

        let claims_b64 = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&claims).map_err(|_| OAuthError::DpopProofFailed)?,
        );

        // Sign `header_b64.claims_b64` bytes with P-256/SHA-256.
        let signing_input = format!("{header_b64}.{claims_b64}");
        let signature: Signature = self.signing_key.sign(signing_input.as_bytes());
        // Normalize to low-S (consistent with the rest of the codebase, even though
        // the relay's DPoP validator does not require it — low-S is harmless and keeps
        // key usage consistent with ATProto expectations).
        let signature = signature.normalize_s().unwrap_or(signature);
        let sig_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes().as_slice());

        Ok(format!("{signing_input}.{sig_b64}"))
    }

    /// Compute `base64url(SHA-256(access_token))` — the `ath` claim for resource requests.
    pub fn compute_ath(access_token: &str) -> String {
        let hash = Sha256::digest(access_token.as_bytes());
        URL_SAFE_NO_PAD.encode(hash)
    }
}
```

**Step 3: Build to verify**

```bash
cargo build -p identity-wallet
```

Expected: builds without errors. Fix any import issues (e.g., if `normalize_s()` is on a different type in this p256 version, try `signature.normalize_s()` returning `Option<Signature>` — call `.unwrap_or(signature)` as shown above).

<!-- END_TASK_3 -->

<!-- START_TASK_4 -->
### Task 4: Write tests for DPoPKeypair

**Verifies:** MM-149.AC3.1, MM-149.AC3.2, MM-149.AC3.3, MM-149.AC3.4, MM-149.AC3.5

**Files:**
- Modify: `apps/identity-wallet/src-tauri/src/oauth.rs` (add `#[cfg(test)]` module)

The relay's DPoP validator is the authoritative spec. Tests should verify our proof passes the same checks the relay performs. We can import and call `relay::auth::dpop::validate_dpop_for_token_endpoint` for AC3.5 verification if the relay is accessible as a workspace crate dependency, but since identity-wallet does not depend on relay, we verify the JWT structure manually by decoding and re-checking the same properties the relay checks.

**Tests must verify:**

- **MM-149.AC3.1:** Decode the base64url header of a generated proof; check `typ = "dpop+jwt"`, `alg = "ES256"`, `jwk.kty = "EC"`, `jwk.crv = "P-256"`, `jwk.x` is non-empty, `jwk.y` is non-empty
- **MM-149.AC3.2:** Decode the base64url claims of a generated proof; check `jti` is non-empty, `htm = "POST"`, `htu = "https://example.com/oauth/token"`, `iat` is within 5 seconds of now
- **MM-149.AC3.3:** Generate a proof with `ath = Some("abc123")`; check `claims.ath = "abc123"`; generate without ath; check `claims.ath` is absent
- **MM-149.AC3.4:** Generate with `nonce = Some("testnonce")`; check `claims.nonce = "testnonce"`; generate without nonce; check `claims.nonce` is absent
- **MM-149.AC3.5:** Verify the proof signature using `p256::ecdsa::VerifyingKey`. Extract the public key from the proof's embedded JWK `x` and `y` coordinates, reconstruct the verifying key, then verify the signature over `header_b64.claims_b64`

**Step 1: Add the test module at the bottom of oauth.rs**

Add:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use p256::ecdsa::signature::Verifier;

    fn decode_jwt_part(b64: &str) -> serde_json::Value {
        let bytes = URL_SAFE_NO_PAD.decode(b64).expect("valid base64url");
        serde_json::from_slice(&bytes).expect("valid JSON")
    }

    fn split_proof(proof: &str) -> (&str, &str, &str) {
        let parts: Vec<&str> = proof.splitn(3, '.').collect();
        assert_eq!(parts.len(), 3, "JWT must have 3 parts");
        (parts[0], parts[1], parts[2])
    }

    #[test]
    fn dpop_proof_header_has_required_fields() {
        // MM-149.AC3.1
        let kp = DPoPKeypair::get_or_create().expect("keypair must generate");
        let proof = kp.make_proof("POST", "https://example.com/oauth/token", None, None)
            .expect("proof must build");
        let (header_b64, _, _) = split_proof(&proof);
        let header = decode_jwt_part(header_b64);

        assert_eq!(header["typ"].as_str(), Some("dpop+jwt"));
        assert_eq!(header["alg"].as_str(), Some("ES256"));
        assert_eq!(header["jwk"]["kty"].as_str(), Some("EC"));
        assert_eq!(header["jwk"]["crv"].as_str(), Some("P-256"));
        assert!(header["jwk"]["x"].as_str().map(|s| !s.is_empty()).unwrap_or(false));
        assert!(header["jwk"]["y"].as_str().map(|s| !s.is_empty()).unwrap_or(false));
    }

    #[test]
    fn dpop_proof_claims_has_required_fields() {
        // MM-149.AC3.2
        let kp = DPoPKeypair::get_or_create().expect("keypair must generate");
        let proof = kp.make_proof("GET", "https://example.com/xrpc/foo", None, None)
            .expect("proof must build");
        let (_, claims_b64, _) = split_proof(&proof);
        let claims = decode_jwt_part(claims_b64);

        assert!(claims["jti"].as_str().map(|s| !s.is_empty()).unwrap_or(false));
        assert_eq!(claims["htm"].as_str(), Some("GET"));
        assert_eq!(claims["htu"].as_str(), Some("https://example.com/xrpc/foo"));
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let iat = claims["iat"].as_i64().expect("iat must be integer");
        assert!((now - iat).abs() < 5, "iat must be within 5 seconds of now");
    }

    #[test]
    fn dpop_proof_includes_ath_when_supplied() {
        // MM-149.AC3.3
        let kp = DPoPKeypair::get_or_create().expect("keypair must generate");
        let proof_with = kp.make_proof("GET", "https://example.com/resource", None, Some("abc123"))
            .expect("proof with ath must build");
        let (_, claims_b64, _) = split_proof(&proof_with);
        let claims = decode_jwt_part(claims_b64);
        assert_eq!(claims["ath"].as_str(), Some("abc123"), "ath must be present");

        let proof_without = kp.make_proof("GET", "https://example.com/resource", None, None)
            .expect("proof without ath must build");
        let (_, claims_b64, _) = split_proof(&proof_without);
        let claims = decode_jwt_part(claims_b64);
        assert!(claims["ath"].is_null(), "ath must be absent when not supplied");
    }

    #[test]
    fn dpop_proof_includes_nonce_when_supplied() {
        // MM-149.AC3.4
        let kp = DPoPKeypair::get_or_create().expect("keypair must generate");
        let proof = kp.make_proof("POST", "https://example.com/oauth/token", Some("nonce123"), None)
            .expect("proof with nonce must build");
        let (_, claims_b64, _) = split_proof(&proof);
        let claims = decode_jwt_part(claims_b64);
        assert_eq!(claims["nonce"].as_str(), Some("nonce123"), "nonce must be present");

        let proof_no = kp.make_proof("POST", "https://example.com/oauth/token", None, None)
            .expect("proof without nonce must build");
        let (_, claims_b64, _) = split_proof(&proof_no);
        let claims = decode_jwt_part(claims_b64);
        assert!(claims["nonce"].is_null(), "nonce must be absent when not supplied");
    }

    #[test]
    fn dpop_proof_signature_verifies_against_embedded_jwk() {
        // MM-149.AC3.5
        use p256::elliptic_curve::sec1::EncodedPoint;

        let kp = DPoPKeypair::get_or_create().expect("keypair must generate");
        let proof = kp.make_proof("POST", "https://example.com/oauth/token", None, None)
            .expect("proof must build");
        let (header_b64, claims_b64, sig_b64) = split_proof(&proof);

        // Reconstruct verifying key from the embedded JWK.
        let header = decode_jwt_part(header_b64);
        let x_bytes = URL_SAFE_NO_PAD.decode(header["jwk"]["x"].as_str().unwrap()).unwrap();
        let y_bytes = URL_SAFE_NO_PAD.decode(header["jwk"]["y"].as_str().unwrap()).unwrap();
        // Build uncompressed point: 0x04 || x || y
        let mut point_bytes = vec![0x04u8];
        point_bytes.extend_from_slice(&x_bytes);
        point_bytes.extend_from_slice(&y_bytes);
        let point = EncodedPoint::from_bytes(&point_bytes).expect("valid uncompressed point");
        let verifying_key = p256::ecdsa::VerifyingKey::from_encoded_point(&point)
            .expect("valid verifying key from JWK");

        // Decode the signature.
        let sig_bytes = URL_SAFE_NO_PAD.decode(sig_b64).expect("valid base64url sig");
        let signature = p256::ecdsa::Signature::from_bytes(sig_bytes.as_slice().into())
            .expect("valid R||S signature bytes");

        // Verify the signature over the signing input.
        let signing_input = format!("{header_b64}.{claims_b64}");
        verifying_key.verify(signing_input.as_bytes(), &signature)
            .expect("signature must verify against embedded JWK");
    }

    #[test]
    fn compute_ath_matches_sha256_base64url() {
        let ath = DPoPKeypair::compute_ath("test_access_token");
        // SHA-256("test_access_token") = known value
        let expected = {
            use sha2::{Digest, Sha256};
            let hash = Sha256::digest(b"test_access_token");
            URL_SAFE_NO_PAD.encode(hash)
        };
        assert_eq!(ath, expected);
    }
}
```

**Step 2: Run the tests**

```bash
cargo test -p identity-wallet dpop
```

Expected output: all 5 tests pass.

**Step 3: Run all identity-wallet tests to confirm no regressions**

```bash
cargo test -p identity-wallet
```

Expected: all tests pass.

**Step 4: Commit**

```bash
git add apps/identity-wallet/src-tauri/Cargo.toml
git add apps/identity-wallet/src-tauri/src/keychain.rs
git add apps/identity-wallet/src-tauri/src/oauth.rs
git commit -m "feat(identity-wallet): DPoP keypair, proof builder, and OAuth Keychain helpers (MM-149 phase 3)"
```

<!-- END_TASK_4 -->

<!-- END_SUBCOMPONENT_B -->
