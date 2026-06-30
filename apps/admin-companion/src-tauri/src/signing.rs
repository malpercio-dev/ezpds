// pattern: Functional Core
//
// The client side of the operator companion's per-device signed-request auth: the
// two canonical envelopes a device signs, byte-for-byte identical to what the relay
// reconstructs and verifies. The relay defines these in `crates/pds/src/routes/auth.rs`
// (`device_registration_sign_string`, `admin_request_sign_string`); this module is the
// single source of truth on the *client* side. The golden tests below pin both formats
// to the same literals the relay's own tests pin, so the two stay in lockstep without a
// cross-crate import (the `pds` crate is binary-only and cannot be depended on).
//
// Pure: no I/O, no key access. `relay_client` feeds these strings to `device_key::sign`
// and attaches the resulting signature to outbound requests.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use sha2::{Digest, Sha256};

/// Headers a paired device attaches to every signed admin request. The relay stores
/// these lowercased (`HeaderMap` normalises on lookup); these canonical `X-Admin-*`
/// forms are what reqwest sends. Pinned here so the client and relay share one
/// definition of the header set.
pub const ADMIN_DEVICE_HEADER: &str = "X-Admin-Device";
pub const ADMIN_TIMESTAMP_HEADER: &str = "X-Admin-Timestamp";
pub const ADMIN_NONCE_HEADER: &str = "X-Admin-Nonce";
pub const ADMIN_SIGNATURE_HEADER: &str = "X-Admin-Signature";

/// The canonical message a device self-signs during registration (`POST /v1/admin/devices`).
///
/// Format: `pairing_code ‖ "\n" ‖ public_key ‖ "\n" ‖ timestamp`. Mirrors the relay's
/// [`device_registration_sign_string`]; proving control of the private key for
/// `public_key` is what authorizes the pairing.
pub fn registration_sign_string(pairing_code: &str, public_key: &str, timestamp: i64) -> String {
    format!("{pairing_code}\n{public_key}\n{timestamp}")
}

/// The canonical envelope a device signs for each admin request, and that the relay's
/// `require_admin` reconstructs to verify it.
///
/// Format: `method ‖ "\n" ‖ path ‖ "\n" ‖ timestamp ‖ "\n" ‖ nonce ‖ "\n" ‖ sha256_hex(body)`.
/// The body is committed to as its lowercase-hex SHA-256 digest (the empty string hashed
/// for a bodiless request). Mirrors the relay's [`admin_request_sign_string`].
pub fn request_sign_string(
    method: &str,
    path: &str,
    timestamp: i64,
    nonce: &str,
    body: &[u8],
) -> String {
    let body_hash = sha256_hex(body);
    format!("{method}\n{path}\n{timestamp}\n{nonce}\n{body_hash}")
}

/// Lowercase hex SHA-256 of `data`. Mirrors the relay's `sha256_hex` byte-for-byte —
/// the body-hash field of the request envelope depends on identical output.
pub fn sha256_hex(data: &[u8]) -> String {
    Sha256::digest(data)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Encode a raw signature (or any bytes) as base64url **without** padding — the wire
/// form the relay decodes for both the registration and per-request signatures.
pub fn encode_signature(raw: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(raw)
}

#[cfg(test)]
mod tests {
    use super::*;

    // SHA-256 of the empty string — the body-hash for every bodiless (e.g. GET) request.
    const EMPTY_SHA256_HEX: &str =
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    #[test]
    fn sha256_hex_matches_known_vectors() {
        // Lowercase hex, no separators — exactly the relay's `sha256_hex` output.
        assert_eq!(sha256_hex(b""), EMPTY_SHA256_HEX);
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn registration_sign_string_matches_relay_golden() {
        // Identical literal to the relay's `sign_string_is_newline_separated` test
        // (crates/pds/src/routes/auth.rs). If either side drifts, this breaks.
        assert_eq!(
            registration_sign_string("CODE", "did:key:zABC", 1700),
            "CODE\ndid:key:zABC\n1700"
        );
    }

    #[test]
    fn request_sign_string_matches_relay_golden() {
        // Identical literal to the relay's `sign_string_is_newline_separated_with_body_hash`
        // test: the final field is the lowercase hex SHA-256 of the (here empty) body.
        assert_eq!(
            request_sign_string("POST", "/x", 1700, "abc", b""),
            format!("POST\n/x\n1700\nabc\n{EMPTY_SHA256_HEX}")
        );
    }

    #[test]
    fn request_sign_string_commits_to_body_bytes() {
        // A different body must change only the trailing hash field, nothing else.
        let a = request_sign_string(
            "POST",
            "/v1/accounts/claim-codes",
            1700,
            "n",
            br#"{"count":1}"#,
        );
        let b = request_sign_string(
            "POST",
            "/v1/accounts/claim-codes",
            1700,
            "n",
            br#"{"count":9}"#,
        );
        assert_ne!(a, b, "distinct bodies must yield distinct envelopes");
        // The prefix up to the final newline is identical; only the hash differs.
        let a_prefix = a.rsplit_once('\n').unwrap().0;
        let b_prefix = b.rsplit_once('\n').unwrap().0;
        assert_eq!(a_prefix, b_prefix);
    }

    #[test]
    fn admin_header_names_lowercase_to_relay_form() {
        // The relay matches headers case-insensitively but stores them lowercased
        // (crates/pds/src/routes/auth.rs ADMIN_*_HEADER). Pin the canonical mapping.
        assert_eq!(ADMIN_DEVICE_HEADER.to_ascii_lowercase(), "x-admin-device");
        assert_eq!(
            ADMIN_TIMESTAMP_HEADER.to_ascii_lowercase(),
            "x-admin-timestamp"
        );
        assert_eq!(ADMIN_NONCE_HEADER.to_ascii_lowercase(), "x-admin-nonce");
        assert_eq!(
            ADMIN_SIGNATURE_HEADER.to_ascii_lowercase(),
            "x-admin-signature"
        );
    }

    #[test]
    fn encode_signature_is_base64url_no_pad() {
        // 0xFF,0xFE,0xFD → base64url-no-pad "__79" (URL-safe alphabet: '_' is index 63,
        // no '=' padding). The same URL_SAFE_NO_PAD engine the relay decodes with.
        assert_eq!(encode_signature(&[0xff, 0xfe, 0xfd]), "__79");
        // A 64-byte zero signature encodes without padding and round-trips back to 64 bytes.
        let encoded = encode_signature(&[0u8; 64]);
        assert!(!encoded.contains('='), "no padding");
        let decoded = URL_SAFE_NO_PAD.decode(&encoded).unwrap();
        assert_eq!(decoded.len(), 64);
    }
}
