// pattern: Functional Core
//
// Pure did:plc genesis operation builder. No I/O, no HTTP, no DB.
// Builds a signed genesis operation from key material and identity fields,
// derives the DID, and returns both for use by the relay's imperative shell.
//
// Algorithm:
//   1. Construct UnsignedPlcOp (fields in DAG-CBOR canonical order)
//   2. CBOR-encode unsigned op (ciborium)
//   3. ECDSA-SHA256 sign the CBOR bytes (p256, RFC 6979 deterministic, low-S)
//   4. base64url-encode the 64-byte r‖s signature
//   5. Construct SignedPlcOp (same fields + sig)
//   6. CBOR-encode signed op
//   7. SHA-256 hash of signed CBOR
//   8. base32-lowercase first 24 chars → DID suffix
//   9. JSON-serialize signed op → signed_op_json
//
// References:
//   - did:plc spec v0.1: https://web.plc.directory/spec/v0.1/did-plc
//   - RFC 6979: deterministic ECDSA nonce generation
//   - DAG-CBOR: map keys sorted by byte-length then alphabetically

use std::collections::BTreeMap;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ciborium::ser::into_writer;
use p256::{
    FieldBytes,
    ecdsa::{SigningKey, Signature, signature::Signer},
};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::{CryptoError, DidKeyUri};

/// The result of building a did:plc genesis operation.
#[derive(Debug)]
pub struct PlcGenesisOp {
    /// The derived DID, e.g. `"did:plc:abcdefghijklmnopqrstuvwx"`.
    /// Ready to use as the database primary key.
    pub did: String,
    /// The signed genesis operation as a JSON string.
    /// Ready to POST to plc.directory.
    pub signed_op_json: String,
}

// ── Internal serialization types ────────────────────────────────────────────
//
// Field declaration order matches DAG-CBOR canonical ordering:
// sort by UTF-8 byte length of the serialized key name, then alphabetically.
//
// For UnsignedPlcOp key lengths:
//   "prev"                 → 4 bytes
//   "type"                 → 4 bytes  ("prev" < "type" alphabetically)
//   "services"             → 8 bytes
//   "alsoKnownAs"          → 11 bytes
//   "rotationKeys"         → 12 bytes
//   "verificationMethods"  → 19 bytes

#[derive(Serialize, Clone)]
struct PlcService {
    // "type" → 4 bytes
    #[serde(rename = "type")]
    service_type: String,
    // "endpoint" → 8 bytes
    endpoint: String,
}

#[derive(Serialize)]
struct UnsignedPlcOp {
    prev: Option<String>,
    #[serde(rename = "type")]
    op_type: String,
    services: BTreeMap<String, PlcService>,
    #[serde(rename = "alsoKnownAs")]
    also_known_as: Vec<String>,
    #[serde(rename = "rotationKeys")]
    rotation_keys: Vec<String>,
    #[serde(rename = "verificationMethods")]
    verification_methods: BTreeMap<String, String>,
}

// For SignedPlcOp key lengths (includes "sig"):
//   "sig"                  → 3 bytes  (shortest — comes first)
//   "prev"                 → 4 bytes
//   "type"                 → 4 bytes
//   "services"             → 8 bytes
//   "alsoKnownAs"          → 11 bytes
//   "rotationKeys"         → 12 bytes
//   "verificationMethods"  → 19 bytes

#[derive(Serialize)]
struct SignedPlcOp {
    sig: String,
    prev: Option<String>,
    #[serde(rename = "type")]
    op_type: String,
    services: BTreeMap<String, PlcService>,
    #[serde(rename = "alsoKnownAs")]
    also_known_as: Vec<String>,
    #[serde(rename = "rotationKeys")]
    rotation_keys: Vec<String>,
    #[serde(rename = "verificationMethods")]
    verification_methods: BTreeMap<String, String>,
}

// ── Public API ───────────────────────────────────────────────────────────────

/// Build and sign a did:plc genesis operation, returning the signed operation
/// JSON and the derived DID.
///
/// # Parameters
/// - `rotation_key`: The user's device key (highest-priority rotation key). Placed at `rotationKeys[0]`.
/// - `signing_key`: The relay's signing key. Placed at `rotationKeys[1]` and `verificationMethods.atproto`.
/// - `signing_private_key`: Raw 32-byte P-256 private key scalar for `signing_key`.
/// - `handle`: The account handle, e.g. `"alice.example.com"`. Stored as `"at://alice.example.com"` in `alsoKnownAs`.
/// - `service_endpoint`: The relay's public URL, e.g. `"https://relay.example.com"`.
///
/// # Errors
/// Returns `CryptoError::PlcOperation` if `signing_private_key` is not a valid P-256 scalar
/// (e.g. all-zero bytes, or a value ≥ the curve order).
pub fn build_did_plc_genesis_op(
    rotation_key: &DidKeyUri,
    signing_key: &DidKeyUri,
    signing_private_key: &[u8; 32],
    handle: &str,
    service_endpoint: &str,
) -> Result<PlcGenesisOp, CryptoError> {
    // Step 1: Construct signing key from raw scalar bytes.
    let field_bytes: FieldBytes = (*signing_private_key).into();
    let sk = SigningKey::from_bytes(&field_bytes)
        .map_err(|e| CryptoError::PlcOperation(format!("invalid signing key: {e}")))?;

    // Step 2: Build the unsigned operation.
    let mut verification_methods = BTreeMap::new();
    verification_methods.insert("atproto".to_string(), signing_key.0.clone());

    let mut services = BTreeMap::new();
    services.insert(
        "atproto_pds".to_string(),
        PlcService {
            service_type: "AtprotoPersonalDataServer".to_string(),
            endpoint: service_endpoint.to_string(),
        },
    );

    let unsigned_op = UnsignedPlcOp {
        prev: None,
        op_type: "plc_operation".to_string(),
        services: services.clone(),
        also_known_as: vec![format!("at://{handle}")],
        rotation_keys: vec![rotation_key.0.clone(), signing_key.0.clone()],
        verification_methods: verification_methods.clone(),
    };

    // Step 3: CBOR-encode the unsigned operation.
    let mut unsigned_cbor = Vec::new();
    into_writer(&unsigned_op, &mut unsigned_cbor)
        .map_err(|e| CryptoError::PlcOperation(format!("cbor encode unsigned op: {e}")))?;

    // Step 4: ECDSA-SHA256 sign (RFC 6979 deterministic, low-S canonical).
    // Signer::sign internally hashes with SHA-256 before signing.
    let sig: Signature = sk.sign(&unsigned_cbor);
    let sig_bytes = sig.to_bytes();

    // Step 5: base64url-encode the 64-byte r‖s signature (no padding).
    let sig_str = URL_SAFE_NO_PAD.encode(&sig_bytes[..]);

    // Step 6: Build the signed operation (same fields + sig).
    let signed_op = SignedPlcOp {
        sig: sig_str,
        prev: None,
        op_type: "plc_operation".to_string(),
        services,
        also_known_as: vec![format!("at://{handle}")],
        rotation_keys: vec![rotation_key.0.clone(), signing_key.0.clone()],
        verification_methods,
    };

    // Step 7: CBOR-encode the signed operation.
    let mut signed_cbor = Vec::new();
    into_writer(&signed_op, &mut signed_cbor)
        .map_err(|e| CryptoError::PlcOperation(format!("cbor encode signed op: {e}")))?;

    // Step 8: SHA-256 hash of the signed CBOR.
    let hash = Sha256::digest(&signed_cbor);

    // Step 9: base32-lowercase, take first 24 characters.
    let base32_encoding = {
        let mut spec = data_encoding::Specification::new();
        spec.symbols.push_str("abcdefghijklmnopqrstuvwxyz234567");
        spec.encoding()
            .map_err(|e| CryptoError::PlcOperation(format!("build base32 encoding: {e}")))?
    };
    let encoded = base32_encoding.encode(hash.as_ref());
    let did = format!("did:plc:{}", &encoded[..24]);

    // Step 10: JSON-serialize the signed operation.
    let signed_op_json = serde_json::to_string(&signed_op)
        .map_err(|e| CryptoError::PlcOperation(format!("json serialize signed op: {e}")))?;

    Ok(PlcGenesisOp { did, signed_op_json })
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generate_p256_keypair;

    /// Generates two test keypairs and calls build_did_plc_genesis_op with them.
    /// Returns (rotation_key, signing_key, private_key_bytes, result).
    fn make_genesis_op() -> (DidKeyUri, DidKeyUri, [u8; 32], PlcGenesisOp) {
        let rotation_kp = generate_p256_keypair().expect("rotation keypair");
        let signing_kp = generate_p256_keypair().expect("signing keypair");
        let private_key_bytes = *signing_kp.private_key_bytes;
        let result = build_did_plc_genesis_op(
            &rotation_kp.key_id,
            &signing_kp.key_id,
            &private_key_bytes,
            "alice.example.com",
            "https://relay.example.com",
        )
        .expect("genesis op should succeed");
        (rotation_kp.key_id, signing_kp.key_id, private_key_bytes, result)
    }

    /// MM-89.AC1.1: did matches ^did:plc:[a-z2-7]{24}$
    #[test]
    fn did_matches_expected_format() {
        let (_, _, _, op) = make_genesis_op();
        assert!(
            op.did.starts_with("did:plc:"),
            "DID should start with 'did:plc:'"
        );
        let suffix = op.did.strip_prefix("did:plc:").unwrap();
        assert_eq!(suffix.len(), 24, "DID suffix should be 24 chars");
        assert!(
            suffix.chars().all(|c| c.is_ascii_lowercase() || ('2'..='7').contains(&c)),
            "DID suffix should only contain [a-z2-7], got: {suffix}"
        );
    }

    /// MM-89.AC1.2: signed_op_json contains all required fields with correct values
    #[test]
    fn signed_op_json_contains_required_fields() {
        let (_, _, _, op) = make_genesis_op();
        let v: serde_json::Value =
            serde_json::from_str(&op.signed_op_json).expect("valid JSON");

        assert_eq!(v["type"], "plc_operation", "type field");
        assert!(v["rotationKeys"].is_array(), "rotationKeys is array");
        assert!(
            v["verificationMethods"].is_object(),
            "verificationMethods is object"
        );
        assert!(v["alsoKnownAs"].is_array(), "alsoKnownAs is array");
        assert!(v["services"].is_object(), "services is object");
        assert_eq!(v["prev"], serde_json::Value::Null, "prev is null");
        assert!(v["sig"].is_string(), "sig is string");
    }

    /// MM-89.AC1.3: rotation_key at rotationKeys[0]; signing_key at rotationKeys[1] and verificationMethods.atproto
    #[test]
    fn keys_placed_in_correct_positions() {
        let (rotation_key, signing_key, _, op) = make_genesis_op();
        let v: serde_json::Value =
            serde_json::from_str(&op.signed_op_json).expect("valid JSON");
        assert_eq!(
            v["rotationKeys"][0].as_str().unwrap(),
            rotation_key.0,
            "rotationKeys[0] should be rotation_key"
        );
        assert_eq!(
            v["rotationKeys"][1].as_str().unwrap(),
            signing_key.0,
            "rotationKeys[1] should be signing_key"
        );
        assert_eq!(
            v["verificationMethods"]["atproto"].as_str().unwrap(),
            signing_key.0,
            "verificationMethods.atproto should be signing_key"
        );
    }

    /// MM-89.AC1.4: RFC 6979 determinism — same inputs produce same DID
    #[test]
    fn same_inputs_produce_same_did() {
        let rotation_kp = generate_p256_keypair().expect("rotation keypair");
        let signing_kp = generate_p256_keypair().expect("signing keypair");
        let private_key_bytes = *signing_kp.private_key_bytes;

        let op1 = build_did_plc_genesis_op(
            &rotation_kp.key_id,
            &signing_kp.key_id,
            &private_key_bytes,
            "alice.example.com",
            "https://relay.example.com",
        )
        .expect("first call should succeed");

        let op2 = build_did_plc_genesis_op(
            &rotation_kp.key_id,
            &signing_kp.key_id,
            &private_key_bytes,
            "alice.example.com",
            "https://relay.example.com",
        )
        .expect("second call should succeed");

        assert_eq!(op1.did, op2.did, "DID must be identical for same inputs");
        assert_eq!(
            op1.signed_op_json, op2.signed_op_json,
            "signed_op_json must be identical for same inputs"
        );
    }

    /// MM-89.AC1.5: Invalid signing key (all-zero scalar) returns CryptoError::PlcOperation
    #[test]
    fn invalid_signing_key_returns_error() {
        let rotation_kp = generate_p256_keypair().expect("rotation keypair");
        let signing_kp = generate_p256_keypair().expect("signing keypair");
        let zero_bytes = [0u8; 32]; // Zero scalar is invalid for P-256

        let result = build_did_plc_genesis_op(
            &rotation_kp.key_id,
            &signing_kp.key_id,
            &zero_bytes,
            "alice.example.com",
            "https://relay.example.com",
        );

        assert!(
            matches!(result, Err(CryptoError::PlcOperation(_))),
            "Zero scalar should return CryptoError::PlcOperation, got: {result:?}"
        );
    }

    /// MM-89.AC3.2: sig field is base64url (no padding) decoding to exactly 64 bytes
    #[test]
    fn sig_field_is_base64url_no_padding_and_64_bytes() {
        let (_, _, _, op) = make_genesis_op();
        let v: serde_json::Value =
            serde_json::from_str(&op.signed_op_json).expect("valid JSON");
        let sig_str = v["sig"].as_str().expect("sig is a string");

        // No padding characters
        assert!(
            !sig_str.contains('='),
            "sig should not contain padding '=', got: {sig_str}"
        );
        // Decodes to exactly 64 bytes
        let decoded = URL_SAFE_NO_PAD
            .decode(sig_str)
            .expect("sig should be valid base64url");
        assert_eq!(
            decoded.len(),
            64,
            "sig should decode to 64 bytes (r‖s), got {} bytes",
            decoded.len()
        );
    }

    /// MM-89.AC3.3: alsoKnownAs contains at://{handle}
    #[test]
    fn also_known_as_contains_at_uri() {
        let rotation_kp = generate_p256_keypair().expect("rotation keypair");
        let signing_kp = generate_p256_keypair().expect("signing keypair");
        let private_key_bytes = *signing_kp.private_key_bytes;

        let op = build_did_plc_genesis_op(
            &rotation_kp.key_id,
            &signing_kp.key_id,
            &private_key_bytes,
            "alice.example.com",
            "https://relay.example.com",
        )
        .expect("genesis op should succeed");

        let v: serde_json::Value =
            serde_json::from_str(&op.signed_op_json).expect("valid JSON");
        let also_known_as = v["alsoKnownAs"].as_array().expect("alsoKnownAs is array");
        assert!(
            also_known_as
                .iter()
                .any(|e| e.as_str() == Some("at://alice.example.com")),
            "alsoKnownAs should contain 'at://alice.example.com', got: {also_known_as:?}"
        );
    }
}
