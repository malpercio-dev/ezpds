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
use multibase;
use p256::{
    ecdsa::{signature::Signer, signature::Verifier, Signature, SigningKey, VerifyingKey},
    FieldBytes,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{keys::P256_MULTICODEC_PREFIX, CryptoError, DidKeyUri};

/// The result of building a did:plc genesis operation.
///
/// Only valid if constructed via [`build_did_plc_genesis_op`] — the
/// `#[non_exhaustive]` attribute ensures that direct construction is not
/// possible outside this module.
#[non_exhaustive]
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

#[derive(Serialize, Deserialize, Clone)]
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

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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

/// The result of verifying a client-submitted did:plc genesis operation.
///
/// Returned by [`verify_genesis_op`]. Fields are extracted directly from the
/// verified signed op; the relay uses them for semantic validation and DID
/// document construction.
///
/// Only valid if constructed via [`verify_genesis_op`] — the `#[non_exhaustive]`
/// attribute ensures that direct construction is not possible outside this
/// module.
#[non_exhaustive]
pub struct VerifiedGenesisOp {
    /// The derived DID, e.g. `"did:plc:abcdefghijklmnopqrstuvwx"`.
    pub did: String,
    /// Full `rotationKeys` array from the op.
    pub rotation_keys: Vec<String>,
    /// Full `alsoKnownAs` array from the op.
    pub also_known_as: Vec<String>,
    /// Full `verificationMethods` map from the op.
    pub verification_methods: BTreeMap<String, String>,
    /// Endpoint from `services["atproto_pds"]`, if present.
    pub atproto_pds_endpoint: Option<String>,
}

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
/// RFC 4648 base32 with lowercase symbols (a-z, 2-7).
/// Used by the did:plc spec to derive the DID from a SHA-256 hash.
fn base32_lowercase() -> Result<data_encoding::Encoding, CryptoError> {
    let mut spec = data_encoding::Specification::new();
    spec.symbols.push_str("abcdefghijklmnopqrstuvwxyz234567");
    spec.encoding()
        .map_err(|e| CryptoError::PlcOperation(format!("build base32 encoding: {e}")))
}

/// Build and sign a did:plc genesis operation using an external signing callback.
///
/// This variant accepts a signing callback instead of raw private key bytes, enabling
/// use with non-extractable keys such as Apple Secure Enclave keys.
///
/// # Parameters
/// - `rotation_key`: The user's device key (highest-priority rotation key). Placed at `rotationKeys[0]`.
/// - `signing_key`: The relay's signing key. Placed at `rotationKeys[1]` and `verificationMethods.atproto`.
/// - `handle`: The account handle, e.g. `"alice.example.com"`. Stored as `"at://alice.example.com"` in `alsoKnownAs`.
/// - `service_endpoint`: The relay's public URL, e.g. `"https://relay.example.com"`.
/// - `sign`: A callback that receives the CBOR-encoded unsigned op bytes and must return the
///   raw 64-byte r‖s P-256 ECDSA signature bytes (big-endian, low-S canonical).
///
/// # Errors
/// Returns `CryptoError::PlcOperation` if `sign` returns `Err`, or if any serialization step fails.
pub fn build_did_plc_genesis_op_with_external_signer<F>(
    rotation_key: &DidKeyUri,
    signing_key: &DidKeyUri,
    handle: &str,
    service_endpoint: &str,
    sign: F,
) -> Result<PlcGenesisOp, CryptoError>
where
    F: FnOnce(&[u8]) -> Result<Vec<u8>, CryptoError>,
{
    // Step 1: Build the unsigned operation.
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

    // Step 2: CBOR-encode the unsigned operation.
    let mut unsigned_cbor = Vec::new();
    into_writer(&unsigned_op, &mut unsigned_cbor)
        .map_err(|e| CryptoError::PlcOperation(format!("cbor encode unsigned op: {e}")))?;

    // Step 3: Call external signer with the CBOR bytes.
    // The callback must return raw 64-byte r‖s P-256 ECDSA signature bytes.
    let sig_bytes = sign(&unsigned_cbor)?;

    if sig_bytes.len() != 64 {
        return Err(CryptoError::PlcOperation(format!(
            "signing callback returned {} bytes, expected 64",
            sig_bytes.len()
        )));
    }

    // Step 4: base64url-encode the signature (no padding).
    let sig_str = URL_SAFE_NO_PAD.encode(&sig_bytes);

    // Step 5: Build the signed operation (same fields + sig).
    let signed_op = SignedPlcOp {
        sig: sig_str,
        prev: None,
        op_type: "plc_operation".to_string(),
        services,
        also_known_as: vec![format!("at://{handle}")],
        rotation_keys: vec![rotation_key.0.clone(), signing_key.0.clone()],
        verification_methods,
    };

    // Step 6: CBOR-encode the signed operation.
    let mut signed_cbor = Vec::new();
    into_writer(&signed_op, &mut signed_cbor)
        .map_err(|e| CryptoError::PlcOperation(format!("cbor encode signed op: {e}")))?;

    // Step 7: SHA-256 hash of the signed CBOR.
    let hash = Sha256::digest(&signed_cbor);

    // Step 8: base32-lowercase, take first 24 characters.
    let encoded = base32_lowercase()?.encode(hash.as_ref());
    let did = format!("did:plc:{}", &encoded[..24]);

    // Step 9: JSON-serialize the signed operation.
    let signed_op_json = serde_json::to_string(&signed_op)
        .map_err(|e| CryptoError::PlcOperation(format!("json serialize signed op: {e}")))?;

    Ok(PlcGenesisOp {
        did,
        signed_op_json,
    })
}

/// Convenience wrapper for callers with extractable P-256 private key bytes.
///
/// Constructs an inline signing callback from the provided private key bytes and delegates to
/// [`build_did_plc_genesis_op_with_external_signer`].
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
    let field_bytes: FieldBytes = (*signing_private_key).into();
    let sk = SigningKey::from_bytes(&field_bytes)
        .map_err(|e| CryptoError::PlcOperation(format!("invalid signing key: {e}")))?;
    build_did_plc_genesis_op_with_external_signer(
        rotation_key,
        signing_key,
        handle,
        service_endpoint,
        |data| {
            let sig: Signature = Signer::sign(&sk, data);
            Ok(sig.to_bytes().to_vec())
        },
    )
}

/// Verify a client-submitted did:plc signed genesis operation.
///
/// Parses `signed_op_json` into a [`SignedPlcOp`] (rejecting unknown fields),
/// validates that this is a genesis operation (not a rotation), reconstructs
/// the unsigned operation with the same DAG-CBOR field ordering as
/// [`build_did_plc_genesis_op`], verifies the ECDSA-SHA256 signature against
/// `rotation_key`, derives the DID (SHA-256 of signed CBOR → base32-lowercase
/// first 24 chars), and returns the extracted operation fields.
///
/// # Important: rotation_key caller obligation
/// The caller is responsible for verifying that the provided `rotation_key`
/// appears in the op's `rotationKeys` array; this function only checks that
/// the signature was made by that key.
///
/// # Parameters
/// - `signed_op_json`: JSON-encoded signed genesis operation from a client.
/// - `rotation_key`: The key that must have signed the unsigned operation — the
///   caller determines which of the op's rotation keys to verify against.
///   Must be a valid `did:key:` URI with P-256 multicodec prefix.
///
/// # Errors
/// Returns `CryptoError::PlcOperation` for any parse, format, cryptographic
/// failure, or if the operation is not a genesis operation (prev != null or
/// type != "plc_operation").
pub fn verify_genesis_op(
    signed_op_json: &str,
    rotation_key: &DidKeyUri,
) -> Result<VerifiedGenesisOp, CryptoError> {
    // Step 1: Parse the signed op, rejecting unknown fields (AC1.5).
    let signed_op: SignedPlcOp = serde_json::from_str(signed_op_json)
        .map_err(|e| CryptoError::PlcOperation(format!("invalid signed op JSON: {e}")))?;

    // Step 2: Validate this is a genesis operation, not a rotation (C2).
    if signed_op.prev.is_some() {
        return Err(CryptoError::PlcOperation(
            "genesis op must have prev = null".to_string(),
        ));
    }
    if signed_op.op_type != "plc_operation" {
        return Err(CryptoError::PlcOperation(format!(
            "expected type 'plc_operation', got '{}'",
            signed_op.op_type
        )));
    }

    // Step 3: Base64url-decode the signature field.
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(&signed_op.sig)
        .map_err(|e| CryptoError::PlcOperation(format!("invalid sig base64url: {e}")))?;

    // Step 4: Parse the 64-byte r‖s fixed-size ECDSA signature.
    let signature = Signature::try_from(sig_bytes.as_slice())
        .map_err(|e| CryptoError::PlcOperation(format!("invalid ECDSA signature bytes: {e}")))?;

    // Step 5: Reconstruct the unsigned operation from signed op fields.
    // Field order must match UnsignedPlcOp's DAG-CBOR canonical ordering.
    let unsigned_op = UnsignedPlcOp {
        prev: signed_op.prev.clone(),
        op_type: signed_op.op_type.clone(),
        services: signed_op.services.clone(),
        also_known_as: signed_op.also_known_as.clone(),
        rotation_keys: signed_op.rotation_keys.clone(),
        verification_methods: signed_op.verification_methods.clone(),
    };

    // Step 6: CBOR-encode the unsigned op — byte-exact match to what was signed.
    let mut unsigned_cbor = Vec::new();
    into_writer(&unsigned_op, &mut unsigned_cbor)
        .map_err(|e| CryptoError::PlcOperation(format!("cbor encode unsigned op: {e}")))?;

    // Step 7: Parse rotation key URI → P-256 VerifyingKey.
    let key_str = rotation_key.0.strip_prefix("did:key:").ok_or_else(|| {
        CryptoError::PlcOperation("rotation key missing did:key: prefix".to_string())
    })?;
    let (_, multikey_bytes) = multibase::decode(key_str)
        .map_err(|e| CryptoError::PlcOperation(format!("decode rotation key multibase: {e}")))?;
    if multikey_bytes.get(..2) != Some(P256_MULTICODEC_PREFIX) {
        return Err(CryptoError::PlcOperation(
            "rotation key is not a P-256 key (wrong multicodec prefix)".to_string(),
        ));
    }
    let verifying_key = VerifyingKey::from_sec1_bytes(&multikey_bytes[2..])
        .map_err(|e| CryptoError::PlcOperation(format!("invalid P-256 public key: {e}")))?;

    // Step 8: Verify the ECDSA-SHA256 signature (SHA-256 applied internally by p256).
    verifying_key
        .verify(&unsigned_cbor, &signature)
        .map_err(|e| CryptoError::PlcOperation(format!("signature verification failed: {e}")))?;

    // Step 9: CBOR-encode the signed op and derive the DID.
    let mut signed_cbor = Vec::new();
    into_writer(&signed_op, &mut signed_cbor)
        .map_err(|e| CryptoError::PlcOperation(format!("cbor encode signed op: {e}")))?;

    let hash = Sha256::digest(&signed_cbor);
    let encoded = base32_lowercase()?.encode(hash.as_ref());
    let did = format!("did:plc:{}", &encoded[..24]);

    // Step 10: Extract atproto_pds endpoint from services map.
    let atproto_pds_endpoint = signed_op
        .services
        .get("atproto_pds")
        .map(|s| s.endpoint.clone());

    Ok(VerifiedGenesisOp {
        did,
        rotation_keys: signed_op.rotation_keys,
        also_known_as: signed_op.also_known_as,
        verification_methods: signed_op.verification_methods,
        atproto_pds_endpoint,
    })
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
        (
            rotation_kp.key_id,
            signing_kp.key_id,
            private_key_bytes,
            result,
        )
    }

    /// did matches ^did:plc:[a-z2-7]{24}$
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
            suffix
                .chars()
                .all(|c| c.is_ascii_lowercase() || ('2'..='7').contains(&c)),
            "DID suffix should only contain [a-z2-7], got: {suffix}"
        );
    }

    /// signed_op_json contains all required fields with correct values
    #[test]
    fn signed_op_json_contains_required_fields() {
        let (_, _, _, op) = make_genesis_op();
        let v: serde_json::Value = serde_json::from_str(&op.signed_op_json).expect("valid JSON");

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

    /// rotation_key at rotationKeys[0]; signing_key at rotationKeys[1] and verificationMethods.atproto
    #[test]
    fn keys_placed_in_correct_positions() {
        let (rotation_key, signing_key, _, op) = make_genesis_op();
        let v: serde_json::Value = serde_json::from_str(&op.signed_op_json).expect("valid JSON");
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

    /// RFC 6979 determinism — same inputs produce same DID
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

    /// Invalid signing key (all-zero scalar) returns CryptoError::PlcOperation
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

    /// sig field is base64url (no padding) decoding to exactly 64 bytes
    #[test]
    fn sig_field_is_base64url_no_padding_and_64_bytes() {
        let (_, _, _, op) = make_genesis_op();
        let v: serde_json::Value = serde_json::from_str(&op.signed_op_json).expect("valid JSON");
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

    /// alsoKnownAs contains at://{handle}
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

        let v: serde_json::Value = serde_json::from_str(&op.signed_op_json).expect("valid JSON");
        let also_known_as = v["alsoKnownAs"].as_array().expect("alsoKnownAs is array");
        assert!(
            also_known_as
                .iter()
                .any(|e| e.as_str() == Some("at://alice.example.com")),
            "alsoKnownAs should contain 'at://alice.example.com', got: {also_known_as:?}"
        );
    }

    // ── verify_genesis_op tests ────────────────────────────────────────────────

    /// Returns (signing_key_uri, PlcGenesisOp) for verify_genesis_op tests.
    /// build_did_plc_genesis_op signs with signing_key_bytes; verify_genesis_op
    /// must receive signing_kp.key_id as its rotation_key argument.
    fn make_op_for_verify() -> (DidKeyUri, PlcGenesisOp) {
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
        .expect("genesis op");
        (signing_kp.key_id, op)
    }

    /// verify_genesis_op returns correct fields
    #[test]
    fn verify_valid_op_returns_correct_fields() {
        let (signing_key, op) = make_op_for_verify();
        let result = verify_genesis_op(&op.signed_op_json, &signing_key);

        assert!(result.is_ok(), "verify should succeed");
        let verified = result.unwrap();

        assert!(
            verified.did.starts_with("did:plc:"),
            "DID should start with 'did:plc:'"
        );
        assert_eq!(
            verified.did.len(),
            32,
            "DID should be 32 chars total (did:plc: + 24 suffix)"
        );
        assert!(
            verified
                .also_known_as
                .contains(&"at://alice.example.com".to_string()),
            "also_known_as should contain 'at://alice.example.com'"
        );
        assert!(
            verified.verification_methods.contains_key("atproto"),
            "verification_methods should contain 'atproto' key"
        );
        assert_eq!(
            verified.atproto_pds_endpoint,
            Some("https://relay.example.com".to_string()),
            "atproto_pds_endpoint should be set correctly"
        );
    }

    /// DID from verify_genesis_op matches build_did_plc_genesis_op
    #[test]
    fn verify_did_matches_build_did_plc_genesis_op() {
        let (signing_key, genesis_op) = make_op_for_verify();
        let verified_result = verify_genesis_op(&genesis_op.signed_op_json, &signing_key);

        assert!(verified_result.is_ok(), "verify should succeed");
        let verified_op = verified_result.unwrap();

        assert_eq!(
            verified_op.did, genesis_op.did,
            "DID from verify_genesis_op should match DID from build_did_plc_genesis_op"
        );
    }

    /// Signature verification fails with wrong rotation key
    #[test]
    fn verify_wrong_rotation_key_returns_error() {
        let (_, op) = make_op_for_verify();
        let wrong_kp = generate_p256_keypair().expect("wrong keypair");

        let result = verify_genesis_op(&op.signed_op_json, &wrong_kp.key_id);

        assert!(
            matches!(result, Err(CryptoError::PlcOperation(_))),
            "Verify with wrong rotation key should return CryptoError::PlcOperation"
        );
    }

    /// Corrupted signature returns error
    #[test]
    fn verify_corrupted_signature_returns_error() {
        let (signing_key, op) = make_op_for_verify();

        // Parse JSON, corrupt the signature field, re-serialize
        let mut v: serde_json::Value =
            serde_json::from_str(&op.signed_op_json).expect("valid JSON");
        let sig_str = v["sig"].as_str().expect("sig is a string");
        let mut sig_bytes = URL_SAFE_NO_PAD
            .decode(sig_str)
            .expect("sig should be valid base64url");
        sig_bytes[0] ^= 0xff; // Flip all bits in first byte
        let corrupted_sig = URL_SAFE_NO_PAD.encode(&sig_bytes);
        v["sig"] = serde_json::json!(corrupted_sig);
        let corrupted_json = serde_json::to_string(&v).expect("re-serialize JSON");

        let result = verify_genesis_op(&corrupted_json, &signing_key);

        assert!(
            matches!(result, Err(CryptoError::PlcOperation(_))),
            "Verify with corrupted signature should return CryptoError::PlcOperation"
        );
    }

    /// Unknown fields in JSON are rejected
    #[test]
    fn verify_unknown_fields_returns_error() {
        let (signing_key, op) = make_op_for_verify();

        // Parse JSON, add an unknown field, re-serialize
        let mut v: serde_json::Value =
            serde_json::from_str(&op.signed_op_json).expect("valid JSON");
        v["unknownField"] = serde_json::json!("surprise");
        let modified_json = serde_json::to_string(&v).expect("re-serialize JSON");

        let result = verify_genesis_op(&modified_json, &signing_key);

        assert!(
            matches!(result, Err(CryptoError::PlcOperation(_))),
            "Verify with unknown fields should return CryptoError::PlcOperation"
        );
    }

    /// Rotation op (prev != null) is rejected
    #[test]
    fn verify_rotation_op_with_non_null_prev_returns_error() {
        let (signing_key, op) = make_op_for_verify();

        // Parse JSON, set prev to a non-null value, re-serialize
        let mut v: serde_json::Value =
            serde_json::from_str(&op.signed_op_json).expect("valid JSON");
        v["prev"] = serde_json::json!("some-hash-value");
        let modified_json = serde_json::to_string(&v).expect("re-serialize JSON");

        let result = verify_genesis_op(&modified_json, &signing_key);

        assert!(
            matches!(result, Err(CryptoError::PlcOperation(_))),
            "Verify with non-null prev should return CryptoError::PlcOperation"
        );
    }

    /// Non-genesis op_type is rejected
    #[test]
    fn verify_non_genesis_op_type_returns_error() {
        let (signing_key, op) = make_op_for_verify();

        // Parse JSON, change type to a rotation type, re-serialize
        let mut v: serde_json::Value =
            serde_json::from_str(&op.signed_op_json).expect("valid JSON");
        v["type"] = serde_json::json!("plc_tombstone");
        let modified_json = serde_json::to_string(&v).expect("re-serialize JSON");

        let result = verify_genesis_op(&modified_json, &signing_key);

        assert!(
            matches!(result, Err(CryptoError::PlcOperation(_))),
            "Verify with non-genesis op_type should return CryptoError::PlcOperation"
        );
    }

    /// Canonical usage pattern — rotation key signs and appears at rotationKeys[0].
    /// The same keypair is both the rotation key and the signing key.
    #[test]
    fn verify_rotation_key_can_verify_own_op() {
        let kp = generate_p256_keypair().expect("keypair");
        let private_key_bytes = *kp.private_key_bytes;

        // Use the SAME keypair as both rotation and signing key.
        // This is the canonical usage: kp appears at rotationKeys[0] AND signs the op.
        let op = build_did_plc_genesis_op(
            &kp.key_id,
            &kp.key_id,
            &private_key_bytes,
            "alice.example.com",
            "https://relay.example.com",
        )
        .expect("genesis op should succeed");

        // Verify using kp.key_id (which appears in rotationKeys[0] AND made the signature).
        let result = verify_genesis_op(&op.signed_op_json, &kp.key_id);

        assert!(
            result.is_ok(),
            "Verify with rotation key that signed and appears at rotationKeys[0] should succeed"
        );
        let verified = result.unwrap();
        assert_eq!(
            verified.did, op.did,
            "DID should match the original op's DID"
        );
    }

    #[test]
    fn external_signer_callback_produces_valid_genesis_op() {
        let rotation_kp = generate_p256_keypair().expect("rotation keypair");
        let signing_kp = generate_p256_keypair().expect("signing keypair");
        let private_key_bytes: [u8; 32] = *signing_kp.private_key_bytes;

        // Simulate SE: the key is available for signing but bytes are not "exposed" to the caller.
        let field_bytes: FieldBytes = private_key_bytes.into();
        let sk = SigningKey::from_bytes(&field_bytes).expect("valid signing key");

        let result = build_did_plc_genesis_op_with_external_signer(
            &rotation_kp.key_id,
            &signing_kp.key_id,
            "alice.example.com",
            "https://relay.example.com",
            |data| {
                let sig: Signature = Signer::sign(&sk, data);
                Ok(sig.to_bytes().to_vec())
            },
        )
        .expect("external signer should succeed");

        // The resulting op must pass verify_genesis_op with the signing key (which made the signature).
        let verified = verify_genesis_op(&result.signed_op_json, &signing_kp.key_id)
            .expect("signed op must be verifiable with signing key");
        assert_eq!(
            verified.did, result.did,
            "verified DID must match the DID returned by the builder"
        );
    }

    #[test]
    fn external_signer_callback_error_propagates_as_plc_operation() {
        let rotation_kp = generate_p256_keypair().expect("rotation keypair");
        let signing_kp = generate_p256_keypair().expect("signing keypair");

        let result = build_did_plc_genesis_op_with_external_signer(
            &rotation_kp.key_id,
            &signing_kp.key_id,
            "alice.example.com",
            "https://relay.example.com",
            |_data| Err(CryptoError::PlcOperation("SE signing failed".to_string())),
        );

        assert!(result.is_err(), "must return error when callback fails");
        match result.unwrap_err() {
            CryptoError::PlcOperation(msg) => {
                assert!(
                    msg.contains("SE signing failed"),
                    "error message must propagate from callback, got: {msg}"
                );
            }
            other => panic!("expected CryptoError::PlcOperation, got: {other:?}"),
        }
    }
}
