// pattern: Functional Core

//! Canonical signed envelope for wallet-authorized account deletion.
//!
//! The second factor of `com.atproto.server.deleteAccount` is the emailed single-use token. The
//! first is normally the account password — which a key-sovereign account may simply not have.
//! Such an account proves the same thing by signing these exact bytes with a key in its
//! authoritative current signing authority (a did:plc rotation set, or a self-hosted did:web's
//! `#device` key), the same proof shape as [`crate::sovereign_session`] and
//! [`crate::oauth_consent`].
//!
//! The deletion *intent* is carried by the domain string and the bound method/path: a proof signed
//! for a sovereign session or an OAuth approval encodes a different domain and so can never be
//! replayed as a deletion, however the bytes are captured.
//!
//! The emailed token is deliberately **not** bound into the envelope. Both factors are already
//! bound to the same account DID and the same one action, so hashing one into the other adds no
//! property the pair does not have — and it would force the wallet to re-sign whenever the user
//! corrects a mistyped code.

/// Protocol domain and version. Changing the wire encoding requires a new domain.
pub const ACCOUNT_DELETE_DOMAIN: &str = "org.obsign.custos.account-delete.v1";
pub const ACCOUNT_DELETE_METHOD: &str = "POST";
pub const ACCOUNT_DELETE_PATH: &str = "/xrpc/com.atproto.server.deleteAccount";

/// Encode the exact bytes signed by an account-deletion client.
///
/// Every value is UTF-8 byte-length-prefixed, so the encoding stays unambiguous even if a future
/// identifier syntax admits separators or newlines. Field order is part of version 1: domain,
/// audience, method, path, account DID, signing-key DID, timestamp, then nonce.
pub fn encode_account_delete_envelope(
    server_did: &str,
    account_did: &str,
    signing_key_did: &str,
    timestamp: i64,
    nonce: &str,
) -> Vec<u8> {
    let timestamp = timestamp.to_string();
    let fields = [
        ("domain", ACCOUNT_DELETE_DOMAIN),
        ("aud", server_did),
        ("method", ACCOUNT_DELETE_METHOD),
        ("path", ACCOUNT_DELETE_PATH),
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

    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct EnvelopeVector {
        server_did: String,
        account_did: String,
        signing_key_did: String,
        timestamp: i64,
        nonce: String,
        envelope: String,
    }

    #[test]
    fn canonical_envelope_has_a_stable_golden_vector() {
        let vector: EnvelopeVector = serde_json::from_str(include_str!(
            "../../../test-vectors/account-delete-envelope-v1.json"
        ))
        .unwrap();
        let encoded = encode_account_delete_envelope(
            &vector.server_did,
            &vector.account_did,
            &vector.signing_key_did,
            vector.timestamp,
            &vector.nonce,
        );
        assert_eq!(String::from_utf8(encoded).unwrap(), vector.envelope);
    }

    #[test]
    fn length_prefixes_prevent_separator_ambiguity() {
        let first =
            encode_account_delete_envelope("did:web:a", "did:plc:b\nc", "did:key:d", 1, "e");
        let second =
            encode_account_delete_envelope("did:web:a", "did:plc:b", "c\ndid:key:d", 1, "e");
        assert_ne!(first, second);
    }

    /// Every binding is inside the signed bytes: a proof for one account, key, moment, or nonce
    /// cannot be re-presented as a proof for another.
    #[test]
    fn every_binding_is_signature_protected() {
        let base = encode_account_delete_envelope("did:web:pds", "did:plc:a", "did:key:k", 10, "n");
        for changed in [
            encode_account_delete_envelope("did:web:other", "did:plc:a", "did:key:k", 10, "n"),
            encode_account_delete_envelope("did:web:pds", "did:plc:b", "did:key:k", 10, "n"),
            encode_account_delete_envelope("did:web:pds", "did:plc:a", "did:key:j", 10, "n"),
            encode_account_delete_envelope("did:web:pds", "did:plc:a", "did:key:k", 11, "n"),
            encode_account_delete_envelope("did:web:pds", "did:plc:a", "did:key:k", 10, "m"),
        ] {
            assert_ne!(base, changed);
        }
    }

    /// The domain is what makes a captured proof surface-specific: the same account, key,
    /// timestamp, and nonce yield different bytes for a session, a consent approval, and a
    /// deletion, so none of the three can be replayed as another.
    #[test]
    fn the_domain_separates_this_surface_from_the_sibling_proofs() {
        let delete =
            encode_account_delete_envelope("did:web:pds", "did:plc:a", "did:key:k", 10, "n");
        let session = crate::sovereign_session::encode_sovereign_session_envelope(
            "did:web:pds",
            "did:plc:a",
            "did:key:k",
            10,
            "n",
        );
        assert_ne!(delete, session);
    }
}
