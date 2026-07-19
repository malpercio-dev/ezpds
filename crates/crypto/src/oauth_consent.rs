// pattern: Functional Core

//! Canonical signed envelope for wallet-confirmed OAuth consent approvals.
//!
//! The wallet approves (or denies) a pending OAuth authorization request by signing these exact
//! bytes with a key in the account's authoritative PLC `rotationKeys` (the same key-sovereign
//! proof shape as [`crate::sovereign_session`]). Binding `request_id`, `client_id`, the decision,
//! and a hash of the granted scope set means an approval cannot be replayed onto a different
//! pending request, flipped from a denial, nor widened to a larger scope set: change any of them
//! and the reconstructed envelope no longer matches the signature.

use sha2::{Digest, Sha256};

/// Protocol domain and version. Changing the wire encoding requires a new domain.
pub const OAUTH_CONSENT_DOMAIN: &str = "org.obsign.custos.oauth-consent.v1";
pub const OAUTH_CONSENT_METHOD: &str = "POST";
pub const OAUTH_CONSENT_APPROVE_PATH: &str = "/oauth/authorize/approve";

/// The two decisions a wallet can sign over a pending request. Bound into the envelope so a
/// captured denial can never be replayed as an (empty-scope) approval, or vice versa.
pub const OAUTH_CONSENT_DECISION_APPROVE: &str = "approve";
pub const OAUTH_CONSENT_DECISION_DENY: &str = "deny";

/// Lowercase-hex SHA-256 of the canonical granted-scope string (space-joined tokens).
///
/// Both the wallet (choosing the granted set) and the server (reconstructing the envelope) hash
/// the identical verbatim string, so the scope binding is agreed without a shared normalizer.
pub fn granted_scope_hash(granted_scope: &str) -> String {
    let digest = Sha256::digest(granted_scope.as_bytes());
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// Encode the exact bytes signed by an OAuth-consent approval/denial client.
///
/// Every value is UTF-8 byte-length-prefixed, so the encoding stays unambiguous even if a future
/// identifier syntax admits separators or newlines. Field order is part of version 1: domain,
/// audience, method, path, account DID, signing-key DID, request id, client id, decision,
/// granted-scope hash, timestamp, then nonce.
///
/// `granted_scope` is the canonical space-joined granted-scope string (empty for a denial); it is
/// bound via its SHA-256 hash ([`granted_scope_hash`]).
#[allow(clippy::too_many_arguments)]
pub fn encode_oauth_consent_envelope(
    server_did: &str,
    account_did: &str,
    signing_key_did: &str,
    request_id: &str,
    client_id: &str,
    decision: &str,
    granted_scope: &str,
    timestamp: i64,
    nonce: &str,
) -> Vec<u8> {
    let timestamp = timestamp.to_string();
    let scope_hash = granted_scope_hash(granted_scope);
    let fields = [
        ("domain", OAUTH_CONSENT_DOMAIN),
        ("aud", server_did),
        ("method", OAUTH_CONSENT_METHOD),
        ("path", OAUTH_CONSENT_APPROVE_PATH),
        ("did", account_did),
        ("key", signing_key_did),
        ("request", request_id),
        ("client", client_id),
        ("decision", decision),
        ("scopeHash", scope_hash.as_str()),
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
        request_id: String,
        client_id: String,
        decision: String,
        granted_scope: String,
        timestamp: i64,
        nonce: String,
        envelope: String,
    }

    #[test]
    fn canonical_envelope_has_a_stable_golden_vector() {
        let vector: EnvelopeVector = serde_json::from_str(include_str!(
            "../../../test-vectors/oauth-consent-envelope-v1.json"
        ))
        .unwrap();
        let encoded = encode_oauth_consent_envelope(
            &vector.server_did,
            &vector.account_did,
            &vector.signing_key_did,
            &vector.request_id,
            &vector.client_id,
            &vector.decision,
            &vector.granted_scope,
            vector.timestamp,
            &vector.nonce,
        );
        assert_eq!(String::from_utf8(encoded).unwrap(), vector.envelope);
    }

    #[test]
    fn length_prefixes_prevent_separator_ambiguity() {
        let first = encode_oauth_consent_envelope(
            "did:web:a",
            "did:plc:b\nc",
            "did:key:d",
            "req",
            "client",
            "approve",
            "atproto",
            1,
            "e",
        );
        let second = encode_oauth_consent_envelope(
            "did:web:a",
            "did:plc:b",
            "c\ndid:key:d",
            "req",
            "client",
            "approve",
            "atproto",
            1,
            "e",
        );
        assert_ne!(first, second);
    }

    #[test]
    fn every_binding_is_signature_protected() {
        let base = encode_oauth_consent_envelope(
            "did:web:pds",
            "did:plc:acct",
            "did:key:k",
            "req-1",
            "client-1",
            "approve",
            "atproto",
            10,
            "n",
        );
        // A different request id, client id, decision, or granted scope set must change the bytes.
        for changed in [
            encode_oauth_consent_envelope(
                "did:web:pds",
                "did:plc:acct",
                "did:key:k",
                "req-2",
                "client-1",
                "approve",
                "atproto",
                10,
                "n",
            ),
            encode_oauth_consent_envelope(
                "did:web:pds",
                "did:plc:acct",
                "did:key:k",
                "req-1",
                "client-2",
                "approve",
                "atproto",
                10,
                "n",
            ),
            encode_oauth_consent_envelope(
                "did:web:pds",
                "did:plc:acct",
                "did:key:k",
                "req-1",
                "client-1",
                "deny",
                "atproto",
                10,
                "n",
            ),
            encode_oauth_consent_envelope(
                "did:web:pds",
                "did:plc:acct",
                "did:key:k",
                "req-1",
                "client-1",
                "approve",
                "atproto transition:generic",
                10,
                "n",
            ),
        ] {
            assert_ne!(base, changed);
        }
    }

    #[test]
    fn granted_scope_hash_is_deterministic_hex() {
        let a = granted_scope_hash("atproto");
        assert_eq!(a.len(), 64);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(a, granted_scope_hash("atproto"));
        assert_ne!(a, granted_scope_hash("atproto transition:generic"));
        assert_ne!(a, granted_scope_hash(""));
    }
}
