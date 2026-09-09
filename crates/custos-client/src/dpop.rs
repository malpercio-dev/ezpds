// pattern: Functional Core

//! [`DpopKeypair`]: RFC 9449 DPoP proof construction/signing, generic over any
//! `ios_device_key::KeychainStore` — the same trait both apps already use for their device
//! keys, reused here rather than inventing a second "byte blob under an account name" seam.
//!
//! **Why not `ios_device_key::sign` itself.** That crate's `sign`/`get_or_create` pair signs
//! caller-supplied bytes without ever exposing the private scalar (the point of the Secure
//! Enclave path). A DPoP proof needs exactly that shape — sign `header_b64.claims_b64` and
//! embed the public JWK — so `DpopKeypair` *could* be rebuilt on top of `ios_device_key::sign`
//! with a dedicated `DeviceKeyAccounts` slot instead of holding a raw exportable scalar here.
//! That is a real improvement (Secure-Enclave-backed proofs on a real device) left for a
//! follow-up: this extraction preserves the wallet's exact current key material and Keychain
//! shape (a raw P-256 scalar under one account) — no Keychain-schema change. It reuses
//! `KeychainStore` at the *trait* level only, which is the portability seam this crate
//! actually needs.
//!
//! One behavior change did land with the move: [`DpopKeypair::get_or_create`] now mints a new
//! key only on a genuine not-found (`K::is_not_found`), where the pre-extraction wallet code
//! minted on *any* Keychain read error, including a locked Keychain or a malformed/wrong-length
//! stored blob. The old behavior could silently replace a device's DPoP key — and every token
//! bound to its old `jkt` — when the Keychain was merely locked, not actually empty. Fixed here
//! rather than carried forward.
//!
//! Proof format: `base64url(header_json).base64url(claims_json).base64url(sig)`, where `sig`
//! is the raw 64-byte low-S-normalized R||S P-256 ECDSA signature of the signing input.

use crate::base64url::b64url_encode;
use ios_device_key::KeychainStore;
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;
use zeroize::Zeroizing;

/// Error type for DPoP keypair and proof operations.
///
/// Variants serialize as `{ "code": "SCREAMING_SNAKE_CASE" }` to match the callers' existing
/// IPC error pattern (`DeviceKeyError`, etc.) — callers that surface this to the frontend do
/// so by mapping it into their own error enum, never by re-exporting these variants directly.
#[derive(Debug, thiserror::Error, serde::Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", tag = "code")]
pub enum DpopError {
    #[error("DPoP keypair generation failed")]
    KeyGenFailed,
    #[error("DPoP keypair is invalid")]
    KeyInvalid,
    #[error("DPoP proof construction failed")]
    ProofFailed,
    #[error("Keychain error: {message}")]
    KeychainError { message: String },
}

/// A P-256 keypair used to produce DPoP proofs.
///
/// The private key scalar (32 bytes) is persisted under a caller-chosen Keychain account, via
/// a caller-chosen `KeychainStore`. The same key is used for all DPoP proofs across app
/// sessions — it is never rotated by this implementation.
pub struct DpopKeypair {
    signing_key: SigningKey,
}

impl DpopKeypair {
    /// Load the DPoP keypair from `account` in `K`'s Keychain, or generate and persist a new
    /// one on a genuine not-found (mirroring `ios_device_key::get_or_create`'s contract: a
    /// locked Keychain or permission failure is a hard error, never treated as "mint a new
    /// key", which would silently orphan whatever the previous key was bound to).
    pub fn get_or_create<K: KeychainStore>(account: &str) -> Result<Self, DpopError> {
        match K::get(account) {
            Ok(bytes) => {
                // Zeroize the loaded scalar on drop — `K::get` returns a plain `Vec<u8>`, which
                // does not zero its buffer itself.
                let bytes = Zeroizing::new(bytes);
                let signing_key =
                    SigningKey::from_slice(&bytes).map_err(|_| DpopError::KeyInvalid)?;
                Ok(Self { signing_key })
            }
            Err(e) if K::is_not_found(&e) => {
                let keypair =
                    crypto::generate_p256_keypair().map_err(|_| DpopError::KeyGenFailed)?;
                // Keep the scalar in its `Zeroizing` wrapper rather than dereferencing it into
                // a plain `[u8; 32]` — a deref-copy would leave the copy un-zeroized on drop.
                let private_bytes = keypair.private_key_bytes;
                K::store(account, &private_bytes[..]).map_err(|e| DpopError::KeychainError {
                    message: e.to_string(),
                })?;
                let signing_key = SigningKey::from_slice(&private_bytes[..])
                    .map_err(|_| DpopError::KeyInvalid)?;
                Ok(Self { signing_key })
            }
            Err(e) => Err(DpopError::KeychainError {
                message: e.to_string(),
            }),
        }
    }

    /// Build the public JWK for this keypair (EC, P-256, kty/crv/x/y only — no private fields).
    ///
    /// The custos's validator expects exactly: `{"kty":"EC","crv":"P-256","x":"<b64url>","y":"<b64url>"}`.
    pub fn public_jwk(&self) -> serde_json::Value {
        let verifying_key = self.signing_key.verifying_key();
        let point = verifying_key.to_encoded_point(false); // false = uncompressed: 04 || x || y
        let x = b64url_encode(point.x().expect("P-256 uncompressed point has x"));
        let y = b64url_encode(point.y().expect("P-256 uncompressed point has y"));
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
    /// This matches the PDS's `jwk_thumbprint()` function in `crates/pds/src/auth/dpop.rs`.
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
        b64url_encode(hash)
    }

    /// Build a DPoP proof JWT for the given HTTP method, URL, and optional claims.
    ///
    /// - `htm`: HTTP method in uppercase, e.g. `"POST"` or `"GET"`
    /// - `htu`: Full target URL without query string, e.g. `"https://relay.ezpds.com/oauth/token"`
    /// - `nonce`: Server-issued nonce from a prior `use_dpop_nonce` 400 response (if any)
    /// - `ath`: `base64url(SHA-256(access_token_ascii))` — required for resource requests; None for token requests
    pub fn make_proof(
        &self,
        htm: &str,
        htu: &str,
        nonce: Option<&str>,
        ath: Option<&str>,
    ) -> Result<String, DpopError> {
        let jwk = self.public_jwk();

        let header = serde_json::json!({
            "typ": "dpop+jwt",
            "alg": "ES256",
            "jwk": jwk,
        });
        let header_b64 =
            b64url_encode(serde_json::to_vec(&header).map_err(|_| DpopError::ProofFailed)?);

        let iat = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| DpopError::ProofFailed)?
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

        let claims_b64 =
            b64url_encode(serde_json::to_vec(&claims).map_err(|_| DpopError::ProofFailed)?);

        let signing_input = format!("{header_b64}.{claims_b64}");
        let signature: Signature = self.signing_key.sign(signing_input.as_bytes());
        // Normalize to low-S (consistent with the rest of the codebase, even though
        // the custos's DPoP validator does not require it — low-S is harmless and keeps
        // key usage consistent with ATProto expectations).
        let signature = signature.normalize_s().unwrap_or(signature);
        let sig_b64 = b64url_encode(signature.to_bytes().as_slice());

        Ok(format!("{signing_input}.{sig_b64}"))
    }

    /// Compute `base64url(SHA-256(access_token))` — the `ath` claim for resource requests.
    pub fn compute_ath(access_token: &str) -> String {
        let hash = Sha256::digest(access_token.as_bytes());
        b64url_encode(hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::base64url::b64url_decode;
    use p256::ecdsa::signature::Verifier;
    use std::collections::HashMap;
    use std::sync::Mutex;

    /// In-memory `KeychainStore` for tests — mirrors the pattern each app's own test-only
    /// Keychain uses (see `ios_device_key`'s test battery).
    struct MemKeychain;

    static STORE: Mutex<Option<HashMap<String, Vec<u8>>>> = Mutex::new(None);

    impl KeychainStore for MemKeychain {
        type Error = String;

        fn get(account: &str) -> Result<Vec<u8>, Self::Error> {
            let guard = STORE.lock().unwrap();
            guard
                .as_ref()
                .and_then(|m| m.get(account).cloned())
                .ok_or_else(|| "not found".to_string())
        }

        fn store(account: &str, data: &[u8]) -> Result<(), Self::Error> {
            let mut guard = STORE.lock().unwrap();
            guard
                .get_or_insert_with(HashMap::new)
                .insert(account.to_string(), data.to_vec());
            Ok(())
        }

        fn delete(account: &str) -> Result<(), Self::Error> {
            let mut guard = STORE.lock().unwrap();
            if let Some(m) = guard.as_mut() {
                m.remove(account);
            }
            Ok(())
        }

        fn is_not_found(error: &Self::Error) -> bool {
            error == "not found"
        }
    }

    /// A fresh, never-reused account name per call — tests run on separate threads, and a
    /// shared account name lets two concurrent "not found" checks race into different
    /// generated keys (this crate's own `is_not_found` contract is fine; the race is
    /// `MemKeychain`'s non-atomic check-then-act, not `get_or_create`'s).
    fn unique_account() -> String {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        format!("test-dpop-key-{}", COUNTER.fetch_add(1, Ordering::Relaxed))
    }

    fn get_or_create() -> DpopKeypair {
        DpopKeypair::get_or_create::<MemKeychain>(&unique_account()).expect("keypair must generate")
    }

    fn decode_jwt_part(b64: &str) -> serde_json::Value {
        let bytes = b64url_decode(b64).expect("valid base64url");
        serde_json::from_slice(&bytes).expect("valid JSON")
    }

    fn split_proof(proof: &str) -> (&str, &str, &str) {
        let parts: Vec<&str> = proof.splitn(3, '.').collect();
        assert_eq!(parts.len(), 3, "JWT must have 3 parts");
        (parts[0], parts[1], parts[2])
    }

    #[test]
    fn get_or_create_is_idempotent() {
        let account = unique_account();
        let a = DpopKeypair::get_or_create::<MemKeychain>(&account).expect("keypair must exist");
        let b = DpopKeypair::get_or_create::<MemKeychain>(&account).expect("keypair must exist");
        assert_eq!(a.public_jwk(), b.public_jwk(), "same key across calls");
    }

    #[test]
    fn dpop_proof_header_has_required_fields() {
        let kp = get_or_create();
        let proof = kp
            .make_proof("POST", "https://example.com/oauth/token", None, None)
            .expect("proof must build");
        let (header_b64, _, _) = split_proof(&proof);
        let header = decode_jwt_part(header_b64);

        assert_eq!(header["typ"].as_str(), Some("dpop+jwt"));
        assert_eq!(header["alg"].as_str(), Some("ES256"));
        assert_eq!(header["jwk"]["kty"].as_str(), Some("EC"));
        assert_eq!(header["jwk"]["crv"].as_str(), Some("P-256"));
        assert!(header["jwk"]["x"]
            .as_str()
            .map(|s| !s.is_empty())
            .unwrap_or(false));
        assert!(header["jwk"]["y"]
            .as_str()
            .map(|s| !s.is_empty())
            .unwrap_or(false));
    }

    #[test]
    fn dpop_proof_claims_has_required_fields() {
        let kp = get_or_create();
        let proof = kp
            .make_proof("GET", "https://example.com/xrpc/foo", None, None)
            .expect("proof must build");
        let (_, claims_b64, _) = split_proof(&proof);
        let claims = decode_jwt_part(claims_b64);

        assert!(claims["jti"]
            .as_str()
            .map(|s| !s.is_empty())
            .unwrap_or(false));
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
        let kp = get_or_create();
        let proof_with = kp
            .make_proof("GET", "https://example.com/resource", None, Some("abc123"))
            .expect("proof with ath must build");
        let (_, claims_b64, _) = split_proof(&proof_with);
        let claims = decode_jwt_part(claims_b64);
        assert_eq!(
            claims["ath"].as_str(),
            Some("abc123"),
            "ath must be present"
        );

        let proof_without = kp
            .make_proof("GET", "https://example.com/resource", None, None)
            .expect("proof without ath must build");
        let (_, claims_b64, _) = split_proof(&proof_without);
        let claims = decode_jwt_part(claims_b64);
        assert!(
            claims["ath"].is_null(),
            "ath must be absent when not supplied"
        );
    }

    #[test]
    fn dpop_proof_includes_nonce_when_supplied() {
        let kp = get_or_create();
        let proof = kp
            .make_proof(
                "POST",
                "https://example.com/oauth/token",
                Some("nonce123"),
                None,
            )
            .expect("proof with nonce must build");
        let (_, claims_b64, _) = split_proof(&proof);
        let claims = decode_jwt_part(claims_b64);
        assert_eq!(
            claims["nonce"].as_str(),
            Some("nonce123"),
            "nonce must be present"
        );

        let proof_no = kp
            .make_proof("POST", "https://example.com/oauth/token", None, None)
            .expect("proof without nonce must build");
        let (_, claims_b64, _) = split_proof(&proof_no);
        let claims = decode_jwt_part(claims_b64);
        assert!(
            claims["nonce"].is_null(),
            "nonce must be absent when not supplied"
        );
    }

    #[test]
    fn dpop_proof_signature_verifies_against_embedded_jwk() {
        use p256::elliptic_curve::sec1::EncodedPoint;

        let kp = get_or_create();
        let proof = kp
            .make_proof("POST", "https://example.com/oauth/token", None, None)
            .expect("proof must build");
        let (header_b64, claims_b64, sig_b64) = split_proof(&proof);

        let header = decode_jwt_part(header_b64);
        let x_bytes = b64url_decode(header["jwk"]["x"].as_str().unwrap()).unwrap();
        let y_bytes = b64url_decode(header["jwk"]["y"].as_str().unwrap()).unwrap();
        let mut point_bytes = vec![0x04u8];
        point_bytes.extend_from_slice(&x_bytes);
        point_bytes.extend_from_slice(&y_bytes);
        let point = EncodedPoint::<p256::NistP256>::from_bytes(&point_bytes)
            .expect("valid uncompressed point");
        let verifying_key = p256::ecdsa::VerifyingKey::from_encoded_point(&point)
            .expect("valid verifying key from JWK");

        let sig_bytes = b64url_decode(sig_b64).expect("valid base64url sig");
        let signature = p256::ecdsa::Signature::from_bytes(sig_bytes.as_slice().into())
            .expect("valid R||S signature bytes");

        let signing_input = format!("{header_b64}.{claims_b64}");
        verifying_key
            .verify(signing_input.as_bytes(), &signature)
            .expect("signature must verify against embedded JWK");
    }

    #[test]
    fn compute_ath_matches_sha256_base64url() {
        let ath = DpopKeypair::compute_ath("test_access_token");
        let expected = {
            use sha2::{Digest, Sha256};
            let hash = Sha256::digest(b"test_access_token");
            b64url_encode(hash)
        };
        assert_eq!(ath, expected);
    }
}
