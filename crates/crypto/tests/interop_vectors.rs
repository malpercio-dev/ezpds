//! Integration tests exercising this crate's signature verification against the
//! official ATProto interop test vectors.
//!
//! Fixtures are CC-0 licensed, from bluesky-social/atproto-interop-tests, and are
//! vendored verbatim under `tests/fixtures/interop/` (see that directory's README
//! for provenance). Loading the real files — rather than hand-transcribing cases —
//! means added upstream vectors are exercised automatically.
//!
//! The signature vectors pin the two atproto verification invariants this crate
//! implements: **low-S canonicalization** (a non-canonical high-S signature must be
//! rejected on both P-256 and secp256k1) and **raw r‖s only** (a DER-encoded
//! signature must be rejected).

use base64::Engine;
use crypto::{did_key_curve, verify_did_key_signature, DidKeyCurve, DidKeyUri};
use serde::Deserialize;
use std::collections::HashSet;

#[derive(Deserialize)]
struct SignatureFixture {
    comment: String,
    #[serde(rename = "messageBase64")]
    message_base64: String,
    algorithm: String,
    #[serde(rename = "publicKeyDid")]
    public_key_did: String,
    #[serde(rename = "signatureBase64")]
    signature_base64: String,
    #[serde(rename = "validSignature")]
    valid_signature: bool,
    tags: Vec<String>,
}

/// Decode a standard-alphabet, unpadded base64 string (the encoding these
/// fixtures use for message and signature bytes).
fn b64(s: &str) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD_NO_PAD
        .decode(s)
        .expect("decode base64 fixture value")
}

fn load_signature_fixtures() -> Vec<SignatureFixture> {
    let raw = include_str!("fixtures/interop/signature-fixtures.json");
    serde_json::from_str(raw).expect("parse signature-fixtures.json")
}

/// Verify a fixture against our verifier, returning whether it was accepted.
///
/// Our API takes a raw 64-byte r‖s signature; a DER-encoded signature (longer
/// than 64 bytes) can't be formed into that array and is rejected up front —
/// which is the correct atproto behavior (DER is forbidden on the wire).
fn fixture_accepts(f: &SignatureFixture) -> bool {
    let key = DidKeyUri(f.public_key_did.clone());
    let message = b64(&f.message_base64);
    match <[u8; 64]>::try_from(b64(&f.signature_base64).as_slice()) {
        Ok(sig) => verify_did_key_signature(&key, &message, &sig).is_ok(),
        Err(_) => false,
    }
}

#[test]
fn signature_fixtures_verify_per_spec() {
    let fixtures = load_signature_fixtures();
    assert!(!fixtures.is_empty(), "signature fixtures must not be empty");

    for f in &fixtures {
        // Cross-check: the fixture's JWT algorithm must match the key's curve.
        let expected_curve = match f.algorithm.as_str() {
            "ES256" => DidKeyCurve::P256,
            "ES256K" => DidKeyCurve::Secp256k1,
            other => panic!("[{}] unexpected algorithm {other:?}", f.comment),
        };
        let key = DidKeyUri(f.public_key_did.clone());
        assert_eq!(
            did_key_curve(&key).expect("did:key must carry a supported curve"),
            expected_curve,
            "[{}] did:key curve must match the algorithm",
            f.comment,
        );

        assert_eq!(
            fixture_accepts(f),
            f.valid_signature,
            "[{}] verification outcome must match validSignature (tags={:?})",
            f.comment,
            f.tags,
        );
    }

    // Guard against an upstream reshuffle silently dropping the invariants these
    // vectors exist to pin: both curves, plus the high-S and DER rejection paths.
    let algorithms: HashSet<&str> = fixtures.iter().map(|f| f.algorithm.as_str()).collect();
    assert!(
        algorithms.contains("ES256") && algorithms.contains("ES256K"),
        "fixtures must cover both P-256 and secp256k1",
    );
    let tags: HashSet<&str> = fixtures
        .iter()
        .flat_map(|f| f.tags.iter().map(String::as_str))
        .collect();
    assert!(
        tags.contains("high-s"),
        "fixtures must exercise the low-S rejection path",
    );
    assert!(
        tags.contains("der-encoded"),
        "fixtures must exercise the DER rejection path",
    );
}

// Deliberately corrupted expectation: a known-valid signature asserted to be
// invalid must trip the gate. If this test *passes* (i.e. does not panic), the
// verification harness above is not actually exercising the signatures.
#[test]
#[should_panic(expected = "verification outcome")]
fn corrupted_signature_expectation_is_detected() {
    let fixtures = load_signature_fixtures();
    let valid = fixtures
        .iter()
        .find(|f| f.valid_signature)
        .expect("fixture set must contain a valid signature");
    assert_eq!(
        fixture_accepts(valid),
        !valid.valid_signature, // negated on purpose
        "verification outcome must (wrongly) be inverted",
    );
}
