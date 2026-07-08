// pattern: Functional Core
//
// Pure did:plc genesis operation builder. No I/O, no HTTP, no DB.
// Builds a signed genesis operation from key material and identity fields,
// derives the DID, and returns both for use by the PDS's imperative shell.
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

/// A service entry in a PLC operation's `services` map.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PlcService {
    /// Service type, e.g. `"AtprotoPersonalDataServer"`.
    #[serde(rename = "type")]
    pub service_type: String,
    /// Service endpoint URL, e.g. `"https://pds.example.com"`.
    pub endpoint: String,
}

/// A string-keyed map that serializes its entries in DAG-CBOR canonical key order: shortest key
/// first, then bytewise. The PLC op structs use this for `services` and `verificationMethods`
/// because `BTreeMap`/`ciborium` emit keys in pure bytewise order, which is NOT canonical
/// DAG-CBOR when keys differ in length (e.g. `atproto_pds` vs `atproto_labeler`) — plc.directory
/// would reject such an op or derive a different DID. Single-entry maps (the common case) are
/// unaffected, so existing genesis DIDs are stable.
#[derive(Clone)]
struct CanonicalMap<V>(BTreeMap<String, V>);

impl<V> CanonicalMap<V> {
    fn into_inner(self) -> BTreeMap<String, V> {
        self.0
    }

    fn get(&self, key: &str) -> Option<&V> {
        self.0.get(key)
    }
}

impl<V: Serialize> Serialize for CanonicalMap<V> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        // DAG-CBOR map key order: by UTF-8 byte length, then bytewise.
        let mut entries: Vec<(&String, &V)> = self.0.iter().collect();
        entries.sort_by(|(a, _), (b, _)| {
            a.len()
                .cmp(&b.len())
                .then_with(|| a.as_bytes().cmp(b.as_bytes()))
        });
        let mut map = serializer.serialize_map(Some(entries.len()))?;
        for (key, value) in entries {
            map.serialize_entry(key, value)?;
        }
        map.end()
    }
}

impl<'de, V: Deserialize<'de>> Deserialize<'de> for CanonicalMap<V> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(Self(BTreeMap::deserialize(deserializer)?))
    }
}

#[derive(Serialize)]
struct UnsignedPlcOp {
    prev: Option<String>,
    #[serde(rename = "type")]
    op_type: String,
    services: CanonicalMap<PlcService>,
    #[serde(rename = "alsoKnownAs")]
    also_known_as: Vec<String>,
    #[serde(rename = "rotationKeys")]
    rotation_keys: Vec<String>,
    #[serde(rename = "verificationMethods")]
    verification_methods: CanonicalMap<String>,
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
    services: CanonicalMap<PlcService>,
    #[serde(rename = "alsoKnownAs")]
    also_known_as: Vec<String>,
    #[serde(rename = "rotationKeys")]
    rotation_keys: Vec<String>,
    #[serde(rename = "verificationMethods")]
    verification_methods: CanonicalMap<String>,
}

// ── CID computation ─────────────────────────────────────────────────────────

/// CIDv1 prefix for dag-cbor + sha-256: version(1) + codec(0x71) + hash(0x12) + length(0x20).
const CIDV1_DAG_CBOR_SHA256_PREFIX: [u8; 4] = [0x01, 0x71, 0x12, 0x20];

/// Compute a CIDv1 (dag-cbor, sha-256) from signed operation CBOR bytes.
///
/// Returns a multibase base32lower-encoded CID string (prefix `b`), matching
/// the format used in did:plc `prev` fields.
///
/// # Parameters
/// - `signed_op_cbor`: DAG-CBOR encoded bytes of a signed PLC operation.
pub fn compute_cid(signed_op_cbor: &[u8]) -> Result<String, CryptoError> {
    let hash = Sha256::digest(signed_op_cbor);
    let mut cid_bytes = Vec::with_capacity(36);
    cid_bytes.extend_from_slice(&CIDV1_DAG_CBOR_SHA256_PREFIX);
    cid_bytes.extend_from_slice(&hash);

    let encoded = base32_lowercase()?.encode(&cid_bytes);
    // Strip padding — multibase base32lower is unpadded
    let encoded = encoded.trim_end_matches('=');
    Ok(format!("b{encoded}"))
}

// ── Public API ───────────────────────────────────────────────────────────────

/// The result of building a signed PLC operation (genesis or rotation).
///
/// Contains the signed operation JSON (ready to POST to plc.directory) and
/// the operation's CID (for use as `prev` in subsequent operations).
#[non_exhaustive]
#[derive(Debug)]
pub struct SignedPlcOperation {
    /// The CID of this operation, for use as `prev` in the next operation.
    pub cid: String,
    /// The signed operation as a JSON string, ready to POST to plc.directory.
    pub signed_op_json: String,
}

/// The result of verifying a client-submitted did:plc genesis operation.
///
/// Returned by [`verify_genesis_op`]. Fields are extracted directly from the
/// verified signed op; the PDS uses them for semantic validation and DID
/// document construction.
///
/// Only valid if constructed via [`verify_genesis_op`] — the `#[non_exhaustive]`
/// attribute ensures that direct construction is not possible outside this
/// module.
#[non_exhaustive]
#[derive(Debug)]
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
/// - `signing_key`: The PDS's signing key. Placed at `rotationKeys[1]` and `verificationMethods.atproto`.
/// - `handle`: The account handle, e.g. `"alice.example.com"`. Stored as `"at://alice.example.com"` in `alsoKnownAs`.
/// - `service_endpoint`: The PDS's public URL, e.g. `"https://pds.example.com"`.
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

    // Wrap the maps so they serialize in DAG-CBOR canonical (length-first) key order.
    let services = CanonicalMap(services);
    let verification_methods = CanonicalMap(verification_methods);

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
    // Reject a non-canonical high-S callback signature before it can build an op that
    // silently fails downstream verification.
    ensure_low_s_callback_signature(&sig_bytes)?;

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
/// - `signing_key`: The PDS's signing key. Placed at `rotationKeys[1]` and `verificationMethods.atproto`.
/// - `signing_private_key`: Raw 32-byte P-256 private key scalar for `signing_key`.
/// - `handle`: The account handle, e.g. `"alice.example.com"`. Stored as `"at://alice.example.com"` in `alsoKnownAs`.
/// - `service_endpoint`: The PDS's public URL, e.g. `"https://pds.example.com"`.
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
            // atproto requires canonical low-S signatures; ~half of raw P-256
            // signatures are high-S and would be rejected by plc.directory.
            // normalize_s() returns Some only when the signature was high-S.
            let sig = sig.normalize_s().unwrap_or(sig);
            Ok(sig.to_bytes().to_vec())
        },
    )
}

/// Build and sign a did:plc rotation operation with an external signing callback.
///
/// Unlike genesis ops, rotation ops have a non-null `prev` field and accept
/// arbitrary rotation keys, verification methods, also-known-as, and services
/// (the caller determines the new state, not this function).
///
/// # Parameters
/// - `prev_cid`: The CID of the previous operation in the chain (from [`compute_cid`]).
/// - `rotation_keys`: The new set of rotation key `did:key:` URIs.
/// - `verification_methods`: Map of method name → `did:key:` URI (e.g. `{"atproto": "did:key:z..."}`).
/// - `also_known_as`: The new set of `alsoKnownAs` URIs (e.g. `["at://alice.example.com"]`).
/// - `services`: Map of service name → [`PlcService`].
/// - `sign`: Callback receiving CBOR-encoded unsigned op bytes; must return raw 64-byte
///   r‖s P-256 ECDSA signature bytes (big-endian, low-S canonical).
///
/// # Errors
/// Returns `CryptoError::PlcOperation` if `sign` returns `Err` or serialization fails.
pub fn build_did_plc_rotation_op<F>(
    prev_cid: &str,
    rotation_keys: Vec<String>,
    verification_methods: BTreeMap<String, String>,
    also_known_as: Vec<String>,
    services: BTreeMap<String, PlcService>,
    sign: F,
) -> Result<SignedPlcOperation, CryptoError>
where
    F: FnOnce(&[u8]) -> Result<Vec<u8>, CryptoError>,
{
    // Wrap the maps so they serialize in DAG-CBOR canonical (length-first) key order.
    let services = CanonicalMap(services);
    let verification_methods = CanonicalMap(verification_methods);

    let unsigned_op = UnsignedPlcOp {
        prev: Some(prev_cid.to_string()),
        op_type: "plc_operation".to_string(),
        services: services.clone(),
        also_known_as: also_known_as.clone(),
        rotation_keys: rotation_keys.clone(),
        verification_methods: verification_methods.clone(),
    };

    // CBOR-encode the unsigned operation.
    let mut unsigned_cbor = Vec::new();
    into_writer(&unsigned_op, &mut unsigned_cbor)
        .map_err(|e| CryptoError::PlcOperation(format!("cbor encode unsigned op: {e}")))?;

    // Sign the CBOR bytes.
    let sig_bytes = sign(&unsigned_cbor)?;
    if sig_bytes.len() != 64 {
        return Err(CryptoError::PlcOperation(format!(
            "signing callback returned {} bytes, expected 64",
            sig_bytes.len()
        )));
    }
    // Reject a non-canonical high-S callback signature (see genesis builder).
    ensure_low_s_callback_signature(&sig_bytes)?;
    let sig_str = URL_SAFE_NO_PAD.encode(&sig_bytes);

    // Build the signed operation.
    let signed_op = SignedPlcOp {
        sig: sig_str,
        prev: Some(prev_cid.to_string()),
        op_type: "plc_operation".to_string(),
        services,
        also_known_as,
        rotation_keys,
        verification_methods,
    };

    // CBOR-encode the signed operation to compute CID.
    let mut signed_cbor = Vec::new();
    into_writer(&signed_op, &mut signed_cbor)
        .map_err(|e| CryptoError::PlcOperation(format!("cbor encode signed op: {e}")))?;

    let cid = compute_cid(&signed_cbor)?;

    // JSON-serialize the signed operation.
    let signed_op_json = serde_json::to_string(&signed_op)
        .map_err(|e| CryptoError::PlcOperation(format!("json serialize signed op: {e}")))?;

    Ok(SignedPlcOperation {
        cid,
        signed_op_json,
    })
}

/// The result of verifying a signed PLC operation (genesis or rotation).
///
/// Returned by [`verify_plc_operation`]. Fields are extracted from the verified
/// signed op; the caller uses them for semantic validation and DID document
/// construction.
#[non_exhaustive]
#[derive(Debug)]
pub struct VerifiedPlcOp {
    /// The derived DID. `Some` for genesis ops (derived from signed CBOR),
    /// `None` for rotation ops (caller provides the DID from context).
    pub did: Option<String>,
    /// The CID of this operation.
    pub cid: String,
    /// The `prev` field: `None` for genesis, `Some(cid)` for rotation.
    pub prev: Option<String>,
    /// Full `rotationKeys` array from the op.
    pub rotation_keys: Vec<String>,
    /// Full `alsoKnownAs` array from the op.
    pub also_known_as: Vec<String>,
    /// Full `verificationMethods` map from the op.
    pub verification_methods: BTreeMap<String, String>,
    /// Full `services` map from the op.
    pub services: BTreeMap<String, PlcService>,
}

/// Verify a signed PLC operation (genesis or rotation).
///
/// Parses `signed_op_json`, reconstructs the unsigned operation with DAG-CBOR
/// canonical field ordering, and verifies the ECDSA-SHA256 signature against
/// each key in `authorized_rotation_keys` until one succeeds.
///
/// # Caller obligation
/// The caller is responsible for providing the correct set of authorized
/// rotation keys. For genesis ops, these come from the op itself; for rotation
/// ops, they come from the **previous** operation's `rotationKeys` array.
/// This function only checks that the signature was made by one of the
/// provided keys — it does not verify that those keys are the right ones
/// for this DID's current state.
///
/// # Parameters
/// - `signed_op_json`: JSON-encoded signed PLC operation.
/// - `authorized_rotation_keys`: The set of `did:key:` URIs authorized to sign
///   this operation.
///
/// # Errors
/// Returns `CryptoError::PlcOperation` if no authorized key verifies the
/// signature, or for any parse/format/cryptographic failure.
pub fn verify_plc_operation(
    signed_op_json: &str,
    authorized_rotation_keys: &[DidKeyUri],
) -> Result<VerifiedPlcOp, CryptoError> {
    if authorized_rotation_keys.is_empty() {
        return Err(CryptoError::PlcOperation(
            "authorized_rotation_keys must not be empty".to_string(),
        ));
    }

    // Fail fast on encoding setup before doing any crypto work.
    let b32 = base32_lowercase()?;

    // Parse the signed op, rejecting unknown fields.
    let signed_op: SignedPlcOp = serde_json::from_str(signed_op_json)
        .map_err(|e| CryptoError::PlcOperation(format!("invalid signed op JSON: {e}")))?;

    if signed_op.op_type != "plc_operation" {
        return Err(CryptoError::PlcOperation(format!(
            "expected type 'plc_operation', got '{}'",
            signed_op.op_type
        )));
    }

    // Base64url-decode the signature.
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(&signed_op.sig)
        .map_err(|e| CryptoError::PlcOperation(format!("invalid sig base64url: {e}")))?;
    let signature = Signature::try_from(sig_bytes.as_slice())
        .map_err(|e| CryptoError::PlcOperation(format!("invalid ECDSA signature bytes: {e}")))?;

    // Reconstruct the unsigned operation.
    let unsigned_op = UnsignedPlcOp {
        prev: signed_op.prev.clone(),
        op_type: signed_op.op_type.clone(),
        services: signed_op.services.clone(),
        also_known_as: signed_op.also_known_as.clone(),
        rotation_keys: signed_op.rotation_keys.clone(),
        verification_methods: signed_op.verification_methods.clone(),
    };

    let mut unsigned_cbor = Vec::new();
    into_writer(&unsigned_op, &mut unsigned_cbor)
        .map_err(|e| CryptoError::PlcOperation(format!("cbor encode unsigned op: {e}")))?;

    // Try each authorized rotation key until one verifies the signature.
    // Accumulate all per-key errors so the caller can diagnose multi-key failures.
    let mut key_errors: Vec<String> = Vec::new();
    for (i, key) in authorized_rotation_keys.iter().enumerate() {
        match verify_signature_with_key(key, &unsigned_cbor, &signature) {
            Ok(()) => {
                // Signature verified — compute DID and CID.
                let mut signed_cbor = Vec::new();
                into_writer(&signed_op, &mut signed_cbor).map_err(|e| {
                    CryptoError::PlcOperation(format!("cbor encode signed op: {e}"))
                })?;

                let cid = compute_cid(&signed_cbor)?;

                // DID is only derivable from genesis ops (prev == None).
                let did = if signed_op.prev.is_none() {
                    let hash = Sha256::digest(&signed_cbor);
                    let encoded = b32.encode(hash.as_ref());
                    Some(format!("did:plc:{}", &encoded[..24]))
                } else {
                    None
                };

                return Ok(VerifiedPlcOp {
                    did,
                    cid,
                    prev: signed_op.prev,
                    rotation_keys: signed_op.rotation_keys,
                    also_known_as: signed_op.also_known_as,
                    verification_methods: signed_op.verification_methods.into_inner(),
                    services: signed_op.services.into_inner(),
                });
            }
            Err(e) => {
                key_errors.push(format!("key[{i}]: {e}"));
            }
        }
    }

    Err(CryptoError::PlcOperation(format!(
        "no authorized rotation key verified the signature: {}",
        key_errors.join("; ")
    )))
}

/// Reject a non-canonical high-S signature returned by an external signing callback.
///
/// The callbacks passed to [`build_did_plc_genesis_op_with_external_signer`] and
/// [`build_did_plc_rotation_op`] are contractually required to return low-S signatures, but a
/// buggy HSM/Secure-Enclave integration that forgot to normalize would otherwise build an op
/// that looks fine yet silently fails every downstream `verify_*` (and whose malleable twin
/// would derive a different DID/CID). Failing fast at build time makes that a loud, local
/// error instead. Callbacks that already normalize (the convenience wrapper, `CommitSigner`,
/// the wallet signers) pass unchanged.
fn ensure_low_s_callback_signature(sig_bytes: &[u8]) -> Result<(), CryptoError> {
    let sig = Signature::try_from(sig_bytes).map_err(|e| {
        CryptoError::PlcOperation(format!(
            "signing callback returned invalid signature bytes: {e}"
        ))
    })?;
    if sig.normalize_s().is_some() {
        return Err(CryptoError::PlcOperation(
            "signing callback returned a non-canonical high-S signature (atproto requires low-S)"
                .to_string(),
        ));
    }
    Ok(())
}

/// Parse a did:key URI into a P-256 VerifyingKey and verify a signature.
/// Returns Ok(()) on success, Err(message) on failure.
///
/// Rejects non-canonical high-S signatures: `p256`'s verify accepts a
/// mathematically valid but malleable high-S form, which atproto verifiers
/// (plc.directory, `@atproto/crypto`) reject. Because PLC DIDs and CIDs are
/// derived from the *signed* CBOR, accepting a malleated sig would let the
/// same signature yield a second valid op with a different DID/CID.
fn verify_signature_with_key(
    key: &DidKeyUri,
    message: &[u8],
    signature: &Signature,
) -> Result<(), String> {
    if signature.normalize_s().is_some() {
        return Err("signature is not low-S canonical (atproto requires low-S)".to_string());
    }
    let key_str = key
        .0
        .strip_prefix("did:key:")
        .ok_or_else(|| "public key missing did:key: prefix".to_string())?;
    let (_, multikey_bytes) =
        multibase::decode(key_str).map_err(|e| format!("decode public key multibase: {e}"))?;
    if multikey_bytes.get(..2) != Some(P256_MULTICODEC_PREFIX) {
        return Err("public key is not a P-256 key (wrong multicodec prefix)".to_string());
    }
    let verifying_key = VerifyingKey::from_sec1_bytes(&multikey_bytes[2..])
        .map_err(|e| format!("invalid P-256 public key: {e}"))?;
    verifying_key
        .verify(message, signature)
        .map_err(|e| format!("signature verification failed: {e}"))
}

/// Verify a raw P-256 ECDSA signature over an arbitrary message.
///
/// A general-purpose verification entry point, decoupled from did:plc
/// operations: the caller supplies the signer's public key, the exact message
/// bytes that were signed, and the raw 64-byte `r‖s` signature. This is the
/// primitive the relay uses to authenticate signed admin requests.
///
/// The message is hashed with SHA-256 internally (ECDSA-SHA256), matching the
/// signing convention used elsewhere in this crate. Pass the message bytes
/// exactly as they were signed — do not pre-hash.
///
/// # Parameters
/// - `public_key`: the signer's P-256 `did:key:` URI (multibase base58btc with
///   the P-256 multicodec prefix).
/// - `message`: the exact bytes that were signed (not pre-hashed).
/// - `signature`: the raw 64-byte `r‖s` ECDSA signature (big-endian).
///
/// # Errors
/// Returns `CryptoError::SignatureVerification` if `public_key` is not a valid
/// P-256 `did:key:` URI, if `signature` is not a parseable `r‖s` ECDSA
/// signature, or if the signature does not verify against the key and message.
pub fn verify_p256_signature(
    public_key: &DidKeyUri,
    message: &[u8],
    signature: &[u8; 64],
) -> Result<(), CryptoError> {
    let signature = Signature::try_from(signature.as_slice()).map_err(|e| {
        CryptoError::SignatureVerification(format!("invalid ECDSA signature bytes: {e}"))
    })?;
    verify_signature_with_key(public_key, message, &signature)
        .map_err(CryptoError::SignatureVerification)
}

// ── Audit log types ─────────────────────────────────────────────────────────

/// A single entry from a plc.directory audit log.
///
/// Returned by [`parse_audit_log`]. The `operation` field contains the raw
/// signed PLC operation as a JSON value; use [`verify_plc_operation`] to
/// validate it cryptographically.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// The DID this operation belongs to.
    pub did: String,
    /// The CID of this operation.
    pub cid: String,
    /// ISO 8601 timestamp when plc.directory received this operation.
    #[serde(rename = "createdAt")]
    pub created_at: String,
    /// Whether plc.directory considers this operation invalidated.
    pub nullified: bool,
    /// The raw signed PLC operation.
    pub operation: serde_json::Value,
}

/// Parse a plc.directory audit log JSON response into a list of entries.
///
/// # Parameters
/// - `json`: The JSON response body from `GET https://plc.directory/{did}/log/audit`.
///
/// # Errors
/// Returns `CryptoError::PlcOperation` if the JSON cannot be parsed.
pub fn parse_audit_log(json: &str) -> Result<Vec<AuditEntry>, CryptoError> {
    serde_json::from_str(json)
        .map_err(|e| CryptoError::PlcOperation(format!("parse audit log: {e}")))
}

/// Find operations in `current` that are not present in `cached`, by CID.
///
/// Returns the new entries in the order they appear in `current`.
pub fn diff_audit_logs(cached: &[AuditEntry], current: &[AuditEntry]) -> Vec<AuditEntry> {
    let cached_cids: std::collections::HashSet<&str> =
        cached.iter().map(|e| e.cid.as_str()).collect();
    current
        .iter()
        .filter(|e| !cached_cids.contains(e.cid.as_str()))
        .cloned()
        .collect()
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

    // Steps 7–8: Parse the rotation key and verify the ECDSA-SHA256 signature
    // (SHA-256 applied internally by p256; low-S canonical form enforced).
    verify_signature_with_key(rotation_key, &unsigned_cbor, &signature)
        .map_err(CryptoError::PlcOperation)?;

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
        verification_methods: signed_op.verification_methods.into_inner(),
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
            "https://pds.example.com",
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
            "https://pds.example.com",
        )
        .expect("first call should succeed");

        let op2 = build_did_plc_genesis_op(
            &rotation_kp.key_id,
            &signing_kp.key_id,
            &private_key_bytes,
            "alice.example.com",
            "https://pds.example.com",
        )
        .expect("second call should succeed");

        assert_eq!(op1.did, op2.did, "DID must be identical for same inputs");
        assert_eq!(
            op1.signed_op_json, op2.signed_op_json,
            "signed_op_json must be identical for same inputs"
        );
    }

    // ── Golden / cross-implementation conformance ──────────────────────────────
    //
    // These pin ezpds's `ciborium` output, derived did:plc, and CIDv1 against values
    // computed independently by `@ipld/dag-cbor` — the canonical DAG-CBOR library used by the
    // JS atproto/plc stack. Because `did = base32(sha256(signed-op CBOR))[..24]`, a matching DID
    // transitively proves the CBOR bytes are byte-identical to the reference: a hash cannot match
    // unless the encodings do. Together these assert ezpds emits canonical DAG-CBOR for the
    // genesis-op shape, so plc.directory will accept it and derive the same DID.
    //
    // Reference values generated with @ipld/dag-cbor for the fixed inputs below. If the genesis
    // op shape ever changes, regenerate them rather than hand-editing.

    const GOLDEN_ROTATION_KEY: &str = "did:key:zDnaeT5tHRpfWmU2y43QQv9LjMcW3oA3JGbHThVgLeC8nsZ5o";
    const GOLDEN_SIGNING_KEY: &str = "did:key:zDnaekzKfClC8Vs9wXkz3FjQ5gQAZmuPV3F3YHc9pTbqyHGYx";
    const GOLDEN_HANDLE: &str = "alice.ezpds.com";
    const GOLDEN_ENDPOINT: &str = "https://pds.ezpds.com";
    // Fixed stand-in signature: raw bytes 1..=64, base64url (no pad).
    const GOLDEN_SIG_BASE64URL: &str =
        "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyAhIiMkJSYnKCkqKywtLi8wMTIzNDU2Nzg5Ojs8PT4_QA";
    const GOLDEN_UNSIGNED_CBOR_HEX: &str = "a66470726576f664747970656d706c635f6f7065726174696f6e687365727669636573a16b617470726f746f5f706473a264747970657819417470726f746f506572736f6e616c4461746153657276657268656e64706f696e747568747470733a2f2f7064732e657a7064732e636f6d6b616c736f4b6e6f776e4173817461743a2f2f616c6963652e657a7064732e636f6d6c726f746174696f6e4b6579738278396469643a6b65793a7a446e616554357448527066576d5532793433515176394c6a4d6357336f41334a476248546856674c6543386e735a356f78396469643a6b65793a7a446e61656b7a4b66436c433856733977586b7a33466a51356751415a6d7550563346335948633970546271794847597873766572696669636174696f6e4d6574686f6473a167617470726f746f78396469643a6b65793a7a446e61656b7a4b66436c433856733977586b7a33466a51356751415a6d75505633463359486339705462717948475978";
    const GOLDEN_SIGNED_CBOR_HEX: &str = "a763736967785641514944424155474277674a4367734d4451345045424553457851564668635947526f62484230654879416849694d6b4a53596e4b436b714b7977744c6938774d54497a4e4455324e7a67354f6a73385054345f51416470726576f664747970656d706c635f6f7065726174696f6e687365727669636573a16b617470726f746f5f706473a264747970657819417470726f746f506572736f6e616c4461746153657276657268656e64706f696e747568747470733a2f2f7064732e657a7064732e636f6d6b616c736f4b6e6f776e4173817461743a2f2f616c6963652e657a7064732e636f6d6c726f746174696f6e4b6579738278396469643a6b65793a7a446e616554357448527066576d5532793433515176394c6a4d6357336f41334a476248546856674c6543386e735a356f78396469643a6b65793a7a446e61656b7a4b66436c433856733977586b7a33466a51356751415a6d7550563346335948633970546271794847597873766572696669636174696f6e4d6574686f6473a167617470726f746f78396469643a6b65793a7a446e61656b7a4b66436c433856733977586b7a33466a51356751415a6d75505633463359486339705462717948475978";
    const GOLDEN_DID: &str = "did:plc:7exl2lz3g2kd37kmzxfp6yrz";
    const GOLDEN_CID: &str = "bafyreihzf26s6ozwsq672tgnzl7weolwff5yskqx4hnryrdrrxvqgbbssm";

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn golden_services() -> CanonicalMap<PlcService> {
        let mut services = BTreeMap::new();
        services.insert(
            "atproto_pds".to_string(),
            PlcService {
                service_type: "AtprotoPersonalDataServer".to_string(),
                endpoint: GOLDEN_ENDPOINT.to_string(),
            },
        );
        CanonicalMap(services)
    }

    fn golden_verification_methods() -> CanonicalMap<String> {
        let mut vms = BTreeMap::new();
        vms.insert("atproto".to_string(), GOLDEN_SIGNING_KEY.to_string());
        CanonicalMap(vms)
    }

    fn golden_signed_op() -> SignedPlcOp {
        SignedPlcOp {
            sig: GOLDEN_SIG_BASE64URL.to_string(),
            prev: None,
            op_type: "plc_operation".to_string(),
            services: golden_services(),
            also_known_as: vec![format!("at://{GOLDEN_HANDLE}")],
            rotation_keys: vec![
                GOLDEN_ROTATION_KEY.to_string(),
                GOLDEN_SIGNING_KEY.to_string(),
            ],
            verification_methods: golden_verification_methods(),
        }
    }

    /// The unsigned op (the bytes that get signed) encodes byte-identically to @ipld/dag-cbor.
    /// If this drifts, the signature would be computed over non-canonical bytes and plc.directory
    /// would reject it.
    #[test]
    fn golden_unsigned_op_cbor_matches_dag_cbor_reference() {
        let op = UnsignedPlcOp {
            prev: None,
            op_type: "plc_operation".to_string(),
            services: golden_services(),
            also_known_as: vec![format!("at://{GOLDEN_HANDLE}")],
            rotation_keys: vec![
                GOLDEN_ROTATION_KEY.to_string(),
                GOLDEN_SIGNING_KEY.to_string(),
            ],
            verification_methods: golden_verification_methods(),
        };
        let mut cbor = Vec::new();
        into_writer(&op, &mut cbor).expect("encode unsigned op");
        assert_eq!(
            hex(&cbor),
            GOLDEN_UNSIGNED_CBOR_HEX,
            "ciborium unsigned-op bytes must equal @ipld/dag-cbor canonical bytes"
        );
    }

    /// The signed op encodes byte-identically to @ipld/dag-cbor (the bytes hashed for the DID).
    #[test]
    fn golden_signed_op_cbor_matches_dag_cbor_reference() {
        let mut cbor = Vec::new();
        into_writer(&golden_signed_op(), &mut cbor).expect("encode signed op");
        assert_eq!(
            hex(&cbor),
            GOLDEN_SIGNED_CBOR_HEX,
            "ciborium signed-op bytes must equal @ipld/dag-cbor canonical bytes"
        );
    }

    /// The full builder derives the same did:plc as the independent reference pipeline
    /// (@ipld/dag-cbor encode → sha256 → base32lower → first 24 chars).
    #[test]
    fn golden_genesis_did_matches_reference() {
        let rotation = DidKeyUri(GOLDEN_ROTATION_KEY.to_string());
        let signing = DidKeyUri(GOLDEN_SIGNING_KEY.to_string());
        let op = build_did_plc_genesis_op_with_external_signer(
            &rotation,
            &signing,
            GOLDEN_HANDLE,
            GOLDEN_ENDPOINT,
            // Fixed stand-in signature: raw bytes 1..=64.
            |_unsigned_cbor| Ok((1u8..=64).collect()),
        )
        .expect("build genesis op");
        assert_eq!(
            op.did, GOLDEN_DID,
            "derived did:plc must match the @ipld/dag-cbor reference"
        );
    }

    /// `compute_cid` (used as `prev` in later ops) matches the reference CIDv1 (dag-cbor, sha-256).
    #[test]
    fn golden_compute_cid_matches_reference() {
        let mut cbor = Vec::new();
        into_writer(&golden_signed_op(), &mut cbor).expect("encode signed op");
        assert_eq!(compute_cid(&cbor).expect("compute_cid"), GOLDEN_CID);
    }

    const GOLDEN_PREV_CID: &str = "bafyreihzf26s6ozwsq672tgnzl7weolwff5yskqx4hnryrdrrxvqgbbssm";
    const GOLDEN_MULTISERVICE_CID: &str =
        "bafyreiaikoz7wscl3eh7jnsnokc5ytbg6q6gtv56rbsautqjz2riufyj5i";

    /// A PLC op with multiple `services` whose keys diverge under bytewise vs DAG-CBOR
    /// length-first ordering — `atproto_pds` (len 11) vs `atproto_labeler` (len 15) — must still
    /// encode canonically (length-first: pds before labeler). `BTreeMap`/`ciborium` would emit
    /// them bytewise (labeler before pds), producing an op plc.directory rejects. Cross-checked
    /// against @ipld/dag-cbor: CID = CIDv1 (dag-cbor, sha-256) of the signed op.
    #[test]
    fn rotation_op_with_multiple_services_encodes_canonically() {
        let mut services = BTreeMap::new();
        services.insert(
            "atproto_pds".to_string(),
            PlcService {
                service_type: "AtprotoPersonalDataServer".to_string(),
                endpoint: GOLDEN_ENDPOINT.to_string(),
            },
        );
        services.insert(
            "atproto_labeler".to_string(),
            PlcService {
                service_type: "AtprotoLabeler".to_string(),
                endpoint: "https://labeler.ezpds.com".to_string(),
            },
        );
        let mut vms = BTreeMap::new();
        vms.insert("atproto".to_string(), GOLDEN_SIGNING_KEY.to_string());

        let op = build_did_plc_rotation_op(
            GOLDEN_PREV_CID,
            vec![
                GOLDEN_ROTATION_KEY.to_string(),
                GOLDEN_SIGNING_KEY.to_string(),
            ],
            vms,
            vec![format!("at://{GOLDEN_HANDLE}")],
            services,
            // Fixed stand-in signature: raw bytes 1..=64.
            |_unsigned_cbor| Ok((1u8..=64).collect()),
        )
        .expect("build rotation op");
        assert_eq!(
            op.cid, GOLDEN_MULTISERVICE_CID,
            "multi-service op must encode in canonical DAG-CBOR key order (length-first)"
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
            "https://pds.example.com",
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

    /// Every signature emitted by the convenience builder is canonical low-S —
    /// plc.directory (via @atproto/crypto) rejects high-S ops, and ~half of raw
    /// P-256 signatures are high-S without normalization.
    #[test]
    fn genesis_op_signatures_are_low_s() {
        for i in 0..32 {
            let (_, _, _, op) = make_genesis_op();
            let v: serde_json::Value =
                serde_json::from_str(&op.signed_op_json).expect("valid JSON");
            let sig_bytes = URL_SAFE_NO_PAD
                .decode(v["sig"].as_str().expect("sig is a string"))
                .expect("sig decodes");
            let sig = Signature::try_from(sig_bytes.as_slice()).expect("parseable signature");
            assert!(
                sig.normalize_s().is_none(),
                "signature must already be canonical low-S (iteration {i})"
            );
        }
    }

    /// Flip a valid op's signature to its high-S (malleable) twin and assert every
    /// verify path rejects it, matching @atproto/crypto's strict verification.
    /// Before low-S enforcement, the twin verified AND derived a different DID.
    #[test]
    fn verify_paths_reject_high_s_signature() {
        let (signing_key, op) = make_op_for_verify();

        let mut v: serde_json::Value =
            serde_json::from_str(&op.signed_op_json).expect("valid JSON");
        let sig_bytes = URL_SAFE_NO_PAD
            .decode(v["sig"].as_str().expect("sig is a string"))
            .expect("sig decodes");
        let low = Signature::try_from(sig_bytes.as_slice()).expect("parseable signature");
        assert!(low.normalize_s().is_none(), "builder must emit low-S");
        // s → n − s: still mathematically valid for the same message and key.
        let high = Signature::from_scalars(low.r().to_bytes(), (-*low.s()).to_bytes())
            .expect("high-S twin is a well-formed signature");
        v["sig"] = serde_json::json!(URL_SAFE_NO_PAD.encode(high.to_bytes()));
        let malleated_json = serde_json::to_string(&v).expect("re-serialize");

        assert!(
            matches!(
                verify_genesis_op(&malleated_json, &signing_key),
                Err(CryptoError::PlcOperation(ref msg)) if msg.contains("low-S")
            ),
            "verify_genesis_op must reject the high-S twin"
        );
        assert!(
            matches!(
                verify_plc_operation(&malleated_json, std::slice::from_ref(&signing_key)),
                Err(CryptoError::PlcOperation(_))
            ),
            "verify_plc_operation must reject the high-S twin"
        );
    }

    /// verify_p256_signature (admin-request auth) also rejects high-S signatures.
    #[test]
    fn verify_p256_signature_rejects_high_s() {
        let message = b"admin request canonical string";
        let (public_key, sig) = sign_message(message);
        let low = Signature::try_from(sig.as_slice()).expect("parseable signature");
        let low = low.normalize_s().unwrap_or(low);
        assert!(
            verify_p256_signature(&public_key, message, &low.to_bytes().into()).is_ok(),
            "low-S signature must verify"
        );
        let high = Signature::from_scalars(low.r().to_bytes(), (-*low.s()).to_bytes())
            .expect("high-S twin is a well-formed signature");
        let high_bytes: [u8; 64] = high.to_bytes().into();
        assert!(
            matches!(
                verify_p256_signature(&public_key, message, &high_bytes),
                Err(CryptoError::SignatureVerification(ref msg)) if msg.contains("low-S")
            ),
            "high-S signature must be rejected"
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
            "https://pds.example.com",
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
            "https://pds.example.com",
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
            Some("https://pds.example.com".to_string()),
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
            "https://pds.example.com",
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
            "https://pds.example.com",
            |data| {
                let sig: Signature = Signer::sign(&sk, data);
                let sig = sig.normalize_s().unwrap_or(sig);
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

    // ── compute_cid tests ─────────────────────────────────────────────────

    /// CID starts with multibase prefix 'b' (base32lower) and contains only [a-z2-7]
    #[test]
    fn compute_cid_returns_valid_multibase_format() {
        let (_, _, _, op) = make_genesis_op();
        // CBOR-encode the signed op to get the bytes compute_cid expects
        let signed_op: serde_json::Value =
            serde_json::from_str(&op.signed_op_json).expect("valid JSON");
        let mut cbor_bytes = Vec::new();
        into_writer(&signed_op, &mut cbor_bytes).expect("cbor encode");

        let cid = compute_cid(&cbor_bytes).expect("compute_cid should succeed");

        assert!(
            cid.starts_with('b'),
            "CID must start with multibase prefix 'b', got: {cid}"
        );
        // After the 'b' prefix, all chars should be base32lower [a-z2-7]
        assert!(
            cid[1..]
                .chars()
                .all(|c| c.is_ascii_lowercase() || ('2'..='7').contains(&c)),
            "CID body should only contain [a-z2-7], got: {cid}"
        );
    }

    /// CID is deterministic: same bytes → same CID
    #[test]
    fn compute_cid_is_deterministic() {
        let data = b"test data for CID computation";
        let cid1 = compute_cid(data).expect("first call");
        let cid2 = compute_cid(data).expect("second call");
        assert_eq!(cid1, cid2, "same input must produce same CID");
    }

    /// Different inputs produce different CIDs
    #[test]
    fn compute_cid_different_inputs_produce_different_cids() {
        let cid1 = compute_cid(b"input one").expect("cid1");
        let cid2 = compute_cid(b"input two").expect("cid2");
        assert_ne!(cid1, cid2, "different inputs must produce different CIDs");
    }

    /// CID encodes a valid CIDv1 structure: version(1) + codec(0x71) + multihash(0x12, 0x20, 32 bytes)
    #[test]
    fn compute_cid_encodes_valid_cidv1_structure() {
        let cid = compute_cid(b"test").expect("compute_cid");

        // Decode: strip multibase prefix 'b', base32-decode the rest
        let body = &cid[1..]; // strip 'b'
        let cid_bytes = base32_lowercase()
            .expect("base32 encoding")
            .decode(body.as_bytes())
            .expect("base32 decode");

        assert_eq!(cid_bytes[0], 0x01, "CID version must be 1");
        assert_eq!(cid_bytes[1], 0x71, "codec must be dag-cbor (0x71)");
        assert_eq!(cid_bytes[2], 0x12, "hash function must be sha-256 (0x12)");
        assert_eq!(cid_bytes[3], 0x20, "hash length must be 32 (0x20)");
        assert_eq!(cid_bytes.len(), 36, "CIDv1 with sha-256 should be 36 bytes");
    }

    // ── verify_plc_operation tests ─────────────────────────────────────────

    #[test]
    fn verify_plc_operation_genesis_op() {
        let (signing_key, op) = make_op_for_verify();
        let result = verify_plc_operation(&op.signed_op_json, &[signing_key]);

        assert!(result.is_ok(), "verify genesis op should succeed");
        let verified = result.unwrap();
        assert_eq!(verified.did, Some(op.did), "DID must match genesis DID");
        assert!(verified.prev.is_none(), "genesis op prev must be None");
        assert!(verified.cid.starts_with('b'), "CID must start with 'b'");
    }

    #[test]
    fn verify_plc_operation_rotation_op() {
        let (signing_key, private_key_bytes, _genesis, prev_cid) = make_genesis_for_rotation();

        let field_bytes: FieldBytes = private_key_bytes.into();
        let sk = SigningKey::from_bytes(&field_bytes).expect("valid key");

        let mut verification_methods = BTreeMap::new();
        verification_methods.insert("atproto".to_string(), signing_key.0.clone());
        let mut services = BTreeMap::new();
        services.insert(
            "atproto_pds".to_string(),
            PlcService {
                service_type: "AtprotoPersonalDataServer".to_string(),
                endpoint: "https://pds.example.com".to_string(),
            },
        );

        let rotation = build_did_plc_rotation_op(
            &prev_cid,
            vec![signing_key.0.clone()],
            verification_methods,
            vec!["at://alice.example.com".to_string()],
            services,
            |data| {
                let sig: Signature = Signer::sign(&sk, data);
                let sig = sig.normalize_s().unwrap_or(sig);
                Ok(sig.to_bytes().to_vec())
            },
        )
        .expect("rotation op");

        // Verify the rotation op with the signing key as authorized
        let verified =
            verify_plc_operation(&rotation.signed_op_json, std::slice::from_ref(&signing_key))
                .expect("verify rotation op");

        assert!(verified.did.is_none(), "rotation op DID must be None");
        assert_eq!(
            verified.prev.as_deref(),
            Some(prev_cid.as_str()),
            "prev must be the genesis CID"
        );
        assert_eq!(verified.cid, rotation.cid, "CID must match builder CID");
    }

    #[test]
    fn verify_plc_operation_rejects_wrong_key() {
        let (_, op) = make_op_for_verify();
        let wrong_kp = generate_p256_keypair().expect("wrong keypair");

        let result = verify_plc_operation(&op.signed_op_json, &[wrong_kp.key_id]);
        assert!(
            matches!(result, Err(CryptoError::PlcOperation(_))),
            "wrong key must fail"
        );
    }

    #[test]
    fn verify_plc_operation_tries_multiple_keys() {
        let (signing_key, op) = make_op_for_verify();
        let wrong_kp = generate_p256_keypair().expect("wrong keypair");

        // Correct key is second in the list — should still succeed
        let result = verify_plc_operation(&op.signed_op_json, &[wrong_kp.key_id, signing_key]);
        assert!(result.is_ok(), "should succeed when correct key is in list");
    }

    #[test]
    fn verify_plc_operation_rejects_empty_key_list() {
        let (_, op) = make_op_for_verify();
        let result = verify_plc_operation(&op.signed_op_json, &[]);
        assert!(
            matches!(result, Err(CryptoError::PlcOperation(ref msg)) if msg.contains("must not be empty")),
            "empty key list must fail"
        );
    }

    /// Tampered rotationKeys in signed JSON must be rejected (signature covers the unsigned op).
    #[test]
    fn verify_plc_operation_rejects_tampered_rotation_keys() {
        let (signing_key, op) = make_op_for_verify();

        // Parse JSON, swap rotationKeys[0] for a different key, re-serialize
        let mut v: serde_json::Value =
            serde_json::from_str(&op.signed_op_json).expect("valid JSON");
        let wrong_kp = generate_p256_keypair().expect("wrong keypair");
        v["rotationKeys"][0] = serde_json::json!(wrong_kp.key_id.0);
        let tampered_json = serde_json::to_string(&v).expect("re-serialize");

        let result = verify_plc_operation(&tampered_json, &[signing_key]);
        assert!(
            matches!(result, Err(CryptoError::PlcOperation(_))),
            "tampered rotationKeys must fail verification"
        );
    }

    /// Non-plc_operation type is rejected by verify_plc_operation.
    #[test]
    fn verify_plc_operation_rejects_non_plc_operation_type() {
        let (signing_key, op) = make_op_for_verify();

        let mut v: serde_json::Value =
            serde_json::from_str(&op.signed_op_json).expect("valid JSON");
        v["type"] = serde_json::json!("plc_tombstone");
        let modified_json = serde_json::to_string(&v).expect("re-serialize");

        let result = verify_plc_operation(&modified_json, &[signing_key]);
        assert!(
            matches!(result, Err(CryptoError::PlcOperation(ref msg)) if msg.contains("plc_tombstone")),
            "non-plc_operation type must be rejected"
        );
    }

    /// Wrong-length signature from rotation op callback hits the length guard.
    #[test]
    fn rotation_op_wrong_length_signature_returns_error() {
        let (signing_key, _, _, prev_cid) = make_genesis_for_rotation();

        let mut verification_methods = BTreeMap::new();
        verification_methods.insert("atproto".to_string(), signing_key.0.clone());

        let result = build_did_plc_rotation_op(
            &prev_cid,
            vec![signing_key.0.clone()],
            verification_methods,
            vec![],
            BTreeMap::new(),
            |_| Ok(vec![0u8; 32]), // 32 bytes instead of expected 64
        );

        assert!(
            matches!(result, Err(CryptoError::PlcOperation(ref msg)) if msg.contains("expected 64")),
            "wrong-length signature must be rejected, got: {result:?}"
        );
    }

    // ── audit log tests ───────────────────────────────────────────────────

    fn sample_audit_log_json() -> String {
        serde_json::to_string(&serde_json::json!([
            {
                "did": "did:plc:abc123",
                "cid": "bafyreiabc",
                "createdAt": "2026-01-01T00:00:00.000Z",
                "nullified": false,
                "operation": {
                    "type": "plc_operation",
                    "prev": null,
                    "sig": "dGVzdA",
                    "rotationKeys": [],
                    "verificationMethods": {},
                    "alsoKnownAs": [],
                    "services": {}
                }
            },
            {
                "did": "did:plc:abc123",
                "cid": "bafyreibcd",
                "createdAt": "2026-01-02T00:00:00.000Z",
                "nullified": false,
                "operation": {
                    "type": "plc_operation",
                    "prev": "bafyreiabc",
                    "sig": "dGVzdDI",
                    "rotationKeys": [],
                    "verificationMethods": {},
                    "alsoKnownAs": [],
                    "services": {}
                }
            }
        ]))
        .unwrap()
    }

    #[test]
    fn parse_audit_log_returns_correct_entries() {
        let json = sample_audit_log_json();
        let entries = parse_audit_log(&json).expect("parse should succeed");

        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].did, "did:plc:abc123");
        assert_eq!(entries[0].cid, "bafyreiabc");
        assert!(!entries[0].nullified);
        assert_eq!(entries[1].cid, "bafyreibcd");
        assert_eq!(entries[1].created_at, "2026-01-02T00:00:00.000Z");
    }

    #[test]
    fn parse_audit_log_rejects_invalid_json() {
        let result = parse_audit_log("not json");
        assert!(matches!(result, Err(CryptoError::PlcOperation(_))));
    }

    #[test]
    fn parse_audit_log_handles_empty_array() {
        let entries = parse_audit_log("[]").expect("empty array");
        assert!(entries.is_empty());
    }

    #[test]
    fn diff_audit_logs_finds_new_entries() {
        let json = sample_audit_log_json();
        let all = parse_audit_log(&json).expect("parse");

        // Cached has only the first entry; current has both
        let cached = &all[..1];
        let new = diff_audit_logs(cached, &all);

        assert_eq!(new.len(), 1);
        assert_eq!(new[0].cid, "bafyreibcd");
    }

    #[test]
    fn diff_audit_logs_returns_empty_when_no_new_entries() {
        let json = sample_audit_log_json();
        let all = parse_audit_log(&json).expect("parse");

        let new = diff_audit_logs(&all, &all);
        assert!(new.is_empty());
    }

    #[test]
    fn diff_audit_logs_returns_all_when_cache_empty() {
        let json = sample_audit_log_json();
        let all = parse_audit_log(&json).expect("parse");

        let new = diff_audit_logs(&[], &all);
        assert_eq!(new.len(), 2);
    }

    // ── build_did_plc_rotation_op tests ─────────────────────────────────────

    /// Helper: build a genesis op and return everything needed to chain a rotation op.
    fn make_genesis_for_rotation() -> (DidKeyUri, [u8; 32], PlcGenesisOp, String) {
        let rotation_kp = generate_p256_keypair().expect("rotation keypair");
        let signing_kp = generate_p256_keypair().expect("signing keypair");
        let private_key_bytes = *signing_kp.private_key_bytes;
        let genesis = build_did_plc_genesis_op(
            &rotation_kp.key_id,
            &signing_kp.key_id,
            &private_key_bytes,
            "alice.example.com",
            "https://pds.example.com",
        )
        .expect("genesis op");

        // Compute the CID of the genesis op for use as prev
        let signed_op: SignedPlcOp =
            serde_json::from_str(&genesis.signed_op_json).expect("parse genesis");
        let mut cbor = Vec::new();
        into_writer(&signed_op, &mut cbor).expect("cbor encode");
        let prev_cid = compute_cid(&cbor).expect("compute cid");

        (signing_kp.key_id, private_key_bytes, genesis, prev_cid)
    }

    #[test]
    fn rotation_op_has_non_null_prev() {
        let (signing_key, private_key_bytes, _, prev_cid) = make_genesis_for_rotation();

        let field_bytes: FieldBytes = private_key_bytes.into();
        let sk = SigningKey::from_bytes(&field_bytes).expect("valid key");

        let mut verification_methods = BTreeMap::new();
        verification_methods.insert("atproto".to_string(), signing_key.0.clone());
        let mut services = BTreeMap::new();
        services.insert(
            "atproto_pds".to_string(),
            PlcService {
                service_type: "AtprotoPersonalDataServer".to_string(),
                endpoint: "https://pds.example.com".to_string(),
            },
        );

        let result = build_did_plc_rotation_op(
            &prev_cid,
            vec![signing_key.0.clone()],
            verification_methods,
            vec!["at://alice.example.com".to_string()],
            services,
            |data| {
                let sig: Signature = Signer::sign(&sk, data);
                let sig = sig.normalize_s().unwrap_or(sig);
                Ok(sig.to_bytes().to_vec())
            },
        )
        .expect("rotation op");

        let v: serde_json::Value =
            serde_json::from_str(&result.signed_op_json).expect("valid JSON");
        assert_eq!(
            v["prev"].as_str().unwrap(),
            prev_cid,
            "prev must match the provided CID"
        );
        assert_eq!(v["type"], "plc_operation");
    }

    #[test]
    fn rotation_op_cid_is_valid_multibase() {
        let (signing_key, private_key_bytes, _, prev_cid) = make_genesis_for_rotation();

        let field_bytes: FieldBytes = private_key_bytes.into();
        let sk = SigningKey::from_bytes(&field_bytes).expect("valid key");

        let mut verification_methods = BTreeMap::new();
        verification_methods.insert("atproto".to_string(), signing_key.0.clone());
        let mut services = BTreeMap::new();
        services.insert(
            "atproto_pds".to_string(),
            PlcService {
                service_type: "AtprotoPersonalDataServer".to_string(),
                endpoint: "https://pds.example.com".to_string(),
            },
        );

        let result = build_did_plc_rotation_op(
            &prev_cid,
            vec![signing_key.0.clone()],
            verification_methods,
            vec!["at://alice.example.com".to_string()],
            services,
            |data| {
                let sig: Signature = Signer::sign(&sk, data);
                let sig = sig.normalize_s().unwrap_or(sig);
                Ok(sig.to_bytes().to_vec())
            },
        )
        .expect("rotation op");

        assert!(
            result.cid.starts_with('b'),
            "CID must start with multibase prefix 'b'"
        );
        assert_ne!(
            result.cid, prev_cid,
            "rotation CID must differ from genesis CID"
        );
    }

    #[test]
    fn rotation_op_signing_error_propagates() {
        let (signing_key, _, _, prev_cid) = make_genesis_for_rotation();

        let mut verification_methods = BTreeMap::new();
        verification_methods.insert("atproto".to_string(), signing_key.0.clone());

        let result = build_did_plc_rotation_op(
            &prev_cid,
            vec![signing_key.0.clone()],
            verification_methods,
            vec![],
            BTreeMap::new(),
            |_| Err(CryptoError::PlcOperation("SE unavailable".to_string())),
        );

        assert!(
            matches!(result, Err(CryptoError::PlcOperation(msg)) if msg.contains("SE unavailable")),
            "signing error must propagate"
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
            "https://pds.example.com",
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

    /// An external signer that returns a high-S signature is rejected at build time, so a
    /// non-canonical op can never be produced (it would fail every downstream verify).
    #[test]
    fn external_signer_high_s_signature_is_rejected_at_build() {
        let rotation_kp = generate_p256_keypair().expect("rotation keypair");
        let signing_kp = generate_p256_keypair().expect("signing keypair");
        let sk = SigningKey::from_bytes(&(*signing_kp.private_key_bytes).into())
            .expect("valid signing key");

        let result = build_did_plc_genesis_op_with_external_signer(
            &rotation_kp.key_id,
            &signing_kp.key_id,
            "alice.example.com",
            "https://pds.example.com",
            |data| {
                // Deliberately return the malleable high-S twin the callback should have normalized.
                let sig: Signature = Signer::sign(&sk, data);
                let low = sig.normalize_s().unwrap_or(sig);
                let high = Signature::from_scalars(low.r().to_bytes(), (-*low.s()).to_bytes())
                    .expect("high-S twin");
                Ok(high.to_bytes().to_vec())
            },
        );

        assert!(
            matches!(result, Err(CryptoError::PlcOperation(ref msg)) if msg.contains("high-S")),
            "high-S callback signature must be rejected at build time, got: {result:?}"
        );
    }

    // ── verify_p256_signature tests ────────────────────────────────────────

    /// Sign `message` with a fresh keypair and return (public_key, raw 64-byte sig).
    fn sign_message(message: &[u8]) -> (DidKeyUri, [u8; 64]) {
        let kp = generate_p256_keypair().expect("keypair");
        let field_bytes: FieldBytes = (*kp.private_key_bytes).into();
        let sk = SigningKey::from_bytes(&field_bytes).expect("valid signing key");
        let sig: Signature = Signer::sign(&sk, message);
        let sig = sig.normalize_s().unwrap_or(sig);
        let sig_bytes: [u8; 64] = sig.to_bytes().into();
        (kp.key_id, sig_bytes)
    }

    /// A valid r‖s signature over the message verifies.
    #[test]
    fn verify_p256_signature_accepts_valid_signature() {
        let message = b"admin request canonical string";
        let (public_key, sig) = sign_message(message);
        assert!(
            verify_p256_signature(&public_key, message, &sig).is_ok(),
            "valid signature should verify"
        );
    }

    /// A signature from a different key is rejected.
    #[test]
    fn verify_p256_signature_rejects_wrong_key() {
        let message = b"admin request canonical string";
        let (_signer, sig) = sign_message(message);
        let other = generate_p256_keypair().expect("other keypair");

        let result = verify_p256_signature(&other.key_id, message, &sig);
        assert!(
            matches!(result, Err(CryptoError::SignatureVerification(_))),
            "signature from a different key must be rejected, got: {result:?}"
        );
    }

    /// A tampered message is rejected.
    #[test]
    fn verify_p256_signature_rejects_tampered_message() {
        let message = b"admin request canonical string";
        let (public_key, sig) = sign_message(message);

        let result = verify_p256_signature(&public_key, b"tampered message", &sig);
        assert!(
            matches!(result, Err(CryptoError::SignatureVerification(_))),
            "signature over a different message must be rejected, got: {result:?}"
        );
    }

    /// A malformed signature (all-zero scalars are out of range) is rejected at parse time.
    #[test]
    fn verify_p256_signature_rejects_malformed_signature() {
        let message = b"admin request canonical string";
        let (public_key, _sig) = sign_message(message);

        let zero_sig = [0u8; 64];
        let result = verify_p256_signature(&public_key, message, &zero_sig);
        assert!(
            matches!(result, Err(CryptoError::SignatureVerification(_))),
            "all-zero (unparseable) signature must be rejected, got: {result:?}"
        );
    }

    /// A non-P-256 / malformed did:key public key is rejected.
    #[test]
    fn verify_p256_signature_rejects_invalid_public_key() {
        let message = b"admin request canonical string";
        let (_signer, sig) = sign_message(message);

        let bad_key = DidKeyUri("not-a-did-key".to_string());
        let result = verify_p256_signature(&bad_key, message, &sig);
        assert!(
            matches!(result, Err(CryptoError::SignatureVerification(_))),
            "malformed public key must be rejected, got: {result:?}"
        );
    }
}
