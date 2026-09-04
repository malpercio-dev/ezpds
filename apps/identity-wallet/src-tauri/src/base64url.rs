// pattern: Functional Core

//! The one base64 alphabet this crate uses — unpadded base64url (RFC 4648 §5), for DPoP
//! proofs, JWT segments, and JWK coordinates. Centralizes the `URL_SAFE_NO_PAD` engine choice
//! so call sites read as "this is base64url" rather than repeating the constant.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

/// Encode bytes as unpadded base64url.
pub(crate) fn b64url_encode(input: impl AsRef<[u8]>) -> String {
    URL_SAFE_NO_PAD.encode(input)
}

/// Decode unpadded base64url. Errors on padded input, non-alphabet characters, or a truncated
/// final group.
pub(crate) fn b64url_decode(input: impl AsRef<[u8]>) -> Result<Vec<u8>, base64::DecodeError> {
    URL_SAFE_NO_PAD.decode(input)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_arbitrary_bytes() {
        let bytes = b"\x00\x01\xfe\xff hello world";
        assert_eq!(b64url_decode(b64url_encode(bytes)).unwrap(), bytes);
    }

    #[test]
    fn encoding_carries_no_padding() {
        // 5 bytes base64-encodes to a length not a multiple of 4, so padded base64 would
        // append `=`; base64url must not.
        assert!(!b64url_encode(b"12345").contains('='));
    }

    #[test]
    fn decode_rejects_padded_input() {
        assert!(b64url_decode("aGVsbG8=").is_err());
    }
}
