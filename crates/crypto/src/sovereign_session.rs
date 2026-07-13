// pattern: Functional Core

//! Canonical signed envelope for Custos sovereign-session proofs.

/// Protocol domain and version. Changing the wire encoding requires a new domain.
pub const SOVEREIGN_SESSION_DOMAIN: &str = "org.obsign.custos.sovereign-session.v1";
pub const SOVEREIGN_SESSION_METHOD: &str = "POST";
pub const SOVEREIGN_SESSION_PATH: &str = "/v1/sessions/sovereign";

/// Encode the exact bytes signed by a sovereign-session client.
///
/// Every value is UTF-8 byte-length-prefixed, so the encoding remains unambiguous even if a
/// future identifier syntax admits separators or newlines. Field order is part of version 1:
/// domain, audience, method, path, account DID, signing-key DID, timestamp, then nonce.
pub fn encode_sovereign_session_envelope(
    server_did: &str,
    account_did: &str,
    signing_key_did: &str,
    timestamp: i64,
    nonce: &str,
) -> Vec<u8> {
    let timestamp = timestamp.to_string();
    let fields = [
        ("domain", SOVEREIGN_SESSION_DOMAIN),
        ("aud", server_did),
        ("method", SOVEREIGN_SESSION_METHOD),
        ("path", SOVEREIGN_SESSION_PATH),
        ("did", account_did),
        ("key", signing_key_did),
        ("timestamp", timestamp.as_str()),
        ("nonce", nonce),
    ];

    let mut encoded = Vec::new();
    for (name, value) in fields {
        encoded.extend_from_slice(name.as_bytes());
        encoded.push(b':');
        encoded.extend_from_slice(value.len().to_string().as_bytes());
        encoded.push(b':');
        encoded.extend_from_slice(value.as_bytes());
        encoded.push(b'\n');
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_envelope_has_a_stable_golden_vector() {
        let encoded = encode_sovereign_session_envelope(
            "did:web:pds.example.com",
            "did:plc:abcdefghijklmnopqrstuvwx",
            "did:key:zExample",
            1_720_000_000,
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        );
        assert_eq!(
            String::from_utf8(encoded).unwrap(),
            "domain:38:org.obsign.custos.sovereign-session.v1\n\
             aud:23:did:web:pds.example.com\n\
             method:4:POST\n\
             path:22:/v1/sessions/sovereign\n\
             did:32:did:plc:abcdefghijklmnopqrstuvwx\n\
             key:16:did:key:zExample\n\
             timestamp:10:1720000000\n\
             nonce:43:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
        );
    }

    #[test]
    fn length_prefixes_prevent_separator_ambiguity() {
        let first =
            encode_sovereign_session_envelope("did:web:a", "did:plc:b\nc", "did:key:d", 1, "e");
        let second =
            encode_sovereign_session_envelope("did:web:a", "did:plc:b", "c\ndid:key:d", 1, "e");
        assert_ne!(first, second);
    }
}
