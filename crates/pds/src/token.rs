// pattern: Functional Core
//
// Token generation and hashing utilities.
//
// All session tokens and device tokens follow the same format:
//   - 32 cryptographically random bytes
//   - Plaintext: base64url-no-pad encoding (43 chars, returned to the client once)
//   - Storage:   SHA-256 hex digest (64 chars, stored in the database)
//
// This module is the single source of truth for that format. Auth verification
// (decode + hash) lives here too so the encoding stays consistent.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};

use common::{ApiError, ErrorCode};

/// A freshly generated token: plaintext for the wire, hash for the database.
pub struct GeneratedToken {
    /// Base64url-no-pad encoded token (43 chars). Returned to the client once.
    pub plaintext: String,
    /// SHA-256 hex digest of the raw bytes (64 chars). Stored in the database.
    pub hash: String,
}

/// Generate a new 32-byte random token.
///
/// Returns the base64url plaintext (for the client) and the SHA-256 hex hash
/// (for database storage). The raw bytes are not retained.
pub fn generate_token() -> GeneratedToken {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    GeneratedToken {
        plaintext: URL_SAFE_NO_PAD.encode(bytes),
        hash: sha256_hex(&bytes),
    }
}

/// SHA-256 hash of `data`, returned as a lowercase hex string (64 chars).
pub fn sha256_hex(data: &[u8]) -> String {
    Sha256::digest(data)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Decode a base64url-no-pad token and return its SHA-256 hex hash.
///
/// Used by auth functions to convert a Bearer token from the wire into the
/// hash format stored in the database.
pub fn hash_bearer_token(base64url_token: &str) -> Result<String, ApiError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(base64url_token)
        .map_err(|_| ApiError::new(ErrorCode::Unauthorized, "invalid session token"))?;
    Ok(sha256_hex(&bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_token_produces_43_char_base64url() {
        let token = generate_token();
        assert_eq!(token.plaintext.len(), 43);
        assert!(token
            .plaintext
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
    }

    #[test]
    fn generate_token_produces_64_char_hex_hash() {
        let token = generate_token();
        assert_eq!(token.hash.len(), 64);
        assert!(token.hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn hash_matches_manual_computation() {
        let token = generate_token();
        let decoded = URL_SAFE_NO_PAD.decode(&token.plaintext).unwrap();
        let expected = sha256_hex(&decoded);
        assert_eq!(token.hash, expected);
    }

    #[test]
    fn hash_bearer_token_round_trips_with_generate() {
        let token = generate_token();
        let hash = hash_bearer_token(&token.plaintext).unwrap();
        assert_eq!(hash, token.hash);
    }

    #[test]
    fn hash_bearer_token_rejects_invalid_base64() {
        let result = hash_bearer_token("not-valid-base64url!!!");
        assert!(result.is_err());
    }

    #[test]
    fn sha256_hex_is_deterministic() {
        let data = b"test data";
        assert_eq!(sha256_hex(data), sha256_hex(data));
    }

    #[test]
    fn different_tokens_produce_different_hashes() {
        let t1 = generate_token();
        let t2 = generate_token();
        assert_ne!(t1.hash, t2.hash);
        assert_ne!(t1.plaintext, t2.plaintext);
    }
}
