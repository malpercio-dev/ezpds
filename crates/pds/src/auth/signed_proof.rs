// pattern: Functional Core

//! Shared decoding primitives for the device-key-signed proof envelopes.
//!
//! Three route surfaces present the same shape of proof — a fresh timestamped envelope signed by a
//! key in the account's authoritative current signing authority, carrying a random nonce:
//! `sovereign_session` (passwordless session issuance), `oauth_consent` (wallet-confirmed consent
//! approval), and `delete_account` (passwordless account deletion). Routes cannot import each
//! other, so the fixed byte lengths and the canonical-encoding check they all enforce live here
//! rather than being restated per route, where the check could drift apart.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

/// Length of an accepted P-256 / secp256k1 signature, in bytes (raw `r || s`).
pub const SIGNATURE_BYTES: usize = 64;

/// Length of an accepted anti-replay nonce, in bytes.
pub const NONCE_BYTES: usize = 32;

/// Decode a value that must be exactly `expected_len` bytes in *canonical* unpadded base64url
/// (re-encoding must reproduce the input), so a proof cannot be re-spelled into a fresh nonce.
pub fn decode_canonical_base64url(value: &str, expected_len: usize) -> Option<Vec<u8>> {
    let decoded = URL_SAFE_NO_PAD.decode(value).ok()?;
    (decoded.len() == expected_len && URL_SAFE_NO_PAD.encode(&decoded) == value).then_some(decoded)
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_value_of_the_expected_length_decodes() {
        let bytes = [7u8; NONCE_BYTES];
        let encoded = URL_SAFE_NO_PAD.encode(bytes);
        assert_eq!(
            decode_canonical_base64url(&encoded, NONCE_BYTES),
            Some(bytes.to_vec())
        );

        let signature = [9u8; SIGNATURE_BYTES];
        let encoded = URL_SAFE_NO_PAD.encode(signature);
        assert_eq!(
            decode_canonical_base64url(&encoded, SIGNATURE_BYTES),
            Some(signature.to_vec())
        );
    }

    #[test]
    fn wrong_length_is_rejected_in_both_directions() {
        let short = URL_SAFE_NO_PAD.encode([0u8; NONCE_BYTES - 1]);
        assert_eq!(decode_canonical_base64url(&short, NONCE_BYTES), None);

        let long = URL_SAFE_NO_PAD.encode([0u8; NONCE_BYTES + 1]);
        assert_eq!(decode_canonical_base64url(&long, NONCE_BYTES), None);

        // A well-formed nonce is not a well-formed signature and vice versa.
        let nonce = URL_SAFE_NO_PAD.encode([0u8; NONCE_BYTES]);
        assert_eq!(decode_canonical_base64url(&nonce, SIGNATURE_BYTES), None);
    }

    #[test]
    fn padded_spelling_of_the_same_bytes_is_rejected() {
        // The canonical spelling is unpadded; `=`-padded input decodes to the same bytes under a
        // laxer engine, which would make one nonce re-spellable and defeat the replay store.
        let padded = format!("{}=", URL_SAFE_NO_PAD.encode([0u8; NONCE_BYTES]));
        assert_eq!(decode_canonical_base64url(&padded, NONCE_BYTES), None);
    }

    #[test]
    fn non_canonical_trailing_bits_are_rejected() {
        // 32 bytes encode to 43 symbols; the final symbol carries 2 unused low bits. Setting them
        // yields a different spelling of the same 32 bytes.
        let canonical = URL_SAFE_NO_PAD.encode([0u8; NONCE_BYTES]);
        assert!(canonical.ends_with('A'));
        let mut respelled = canonical[..canonical.len() - 1].to_string();
        respelled.push('B');
        assert_ne!(respelled, canonical);
        assert_eq!(decode_canonical_base64url(&respelled, NONCE_BYTES), None);
    }

    #[test]
    fn standard_base64_alphabet_and_junk_are_rejected() {
        // `+` and `/` are the standard alphabet's substitutes for url-safe `-` and `_`.
        let standard =
            base64::engine::general_purpose::STANDARD_NO_PAD.encode([0xffu8; NONCE_BYTES]);
        assert!(standard.contains('+') || standard.contains('/'));
        assert_eq!(decode_canonical_base64url(&standard, NONCE_BYTES), None);

        assert_eq!(decode_canonical_base64url("", NONCE_BYTES), None);
        assert_eq!(decode_canonical_base64url("not base64!", NONCE_BYTES), None);
    }
}
