//! Golden wire-format vectors for the notification-relay HPKE envelope.
//!
//! RFC 9180's appendix carries no test vector for this exact suite — A.3 is
//! DHKEM(P-256)+AES-**128**-GCM, while CryptoKit's only P-256 suite forces AES-**256**-GCM —
//! so these vectors are self-generated from this implementation and pinned here. Their job
//! is not to prove RFC conformance (the `hpke` crate's own KAT suite does that) but to
//! **freeze the wire format**: if the pinned suite, the `info` string, the `aad`, or the
//! key encodings ever drift, `open` stops round-tripping these bytes and the change surfaces
//! as a failing test instead of as devices that silently stop decrypting.
//!
//! Cross-verification against CryptoKit happens on-device in the wallet phase: the same
//! fixtures are read by an XCTest that opens them with `HPKE.Recipient`.

use base64::Engine;
use crypto::{open_notification, public_key_for_secret, seal_notification};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct NotifyVector {
    comment: String,
    sender_private_key_bytes: Vec<u8>,
    sender_public_key_base64: String,
    recipient_private_key_bytes: Vec<u8>,
    recipient_public_key_base64: String,
    plaintext_base64: String,
    enc_base64: String,
    ct_base64: String,
}

fn b64(s: &str) -> Vec<u8> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .expect("decode base64url fixture value")
}

/// Private keys are stored as byte arrays rather than base64 strings on purpose: they are
/// deterministic test-only material, and a base64-encoded 32-byte scalar is indistinguishable
/// to a secret scanner from a real leaked credential. The array form keeps the fixtures
/// honest without teaching anyone to ignore their scanner.
fn key(bytes: &[u8]) -> [u8; 32] {
    bytes.try_into().expect("32-byte private key")
}

fn vectors() -> Vec<NotifyVector> {
    let raw = include_str!("fixtures/notify/hpke-notify-v1.json");
    serde_json::from_str(raw).expect("parse notify fixtures")
}

#[test]
fn fixtures_open_to_their_plaintext() {
    let vectors = vectors();
    assert!(!vectors.is_empty());

    for v in &vectors {
        let opened = open_notification(
            &key(&v.recipient_private_key_bytes),
            &b64(&v.sender_public_key_base64),
            &b64(&v.enc_base64),
            &b64(&v.ct_base64),
        )
        .unwrap_or_else(|e| panic!("open failed for {:?}: {e}", v.comment));

        assert_eq!(opened, b64(&v.plaintext_base64), "{}", v.comment);
    }
}

#[test]
fn fixture_keypairs_are_self_consistent() {
    for v in vectors() {
        assert_eq!(
            public_key_for_secret(&key(&v.sender_private_key_bytes)).unwrap(),
            b64(&v.sender_public_key_base64),
            "{}",
            v.comment
        );
        assert_eq!(
            public_key_for_secret(&key(&v.recipient_private_key_bytes)).unwrap(),
            b64(&v.recipient_public_key_base64),
            "{}",
            v.comment
        );
    }
}

#[test]
fn fixture_wire_shapes_are_pinned() {
    for v in vectors() {
        // Encapsulated key: uncompressed SEC1 P-256 point, always 65 bytes → 87 base64url chars.
        assert_eq!(b64(&v.enc_base64).len(), 65, "{}", v.comment);
        assert_eq!(v.enc_base64.len(), 87, "{}", v.comment);
        // Ciphertext carries the 16-byte AES-256-GCM tag and nothing else.
        assert_eq!(
            b64(&v.ct_base64).len(),
            b64(&v.plaintext_base64).len() + 16,
            "{}",
            v.comment
        );
    }
}

#[test]
fn freshly_sealed_payloads_open_against_the_fixture_keys() {
    // The fixtures pin `open`; this pins that `seal` still produces something the same
    // pinned parameters can open — a suite or info-string change breaks both directions.
    for v in vectors() {
        let plaintext = b64(&v.plaintext_base64);
        let sealed = seal_notification(
            &key(&v.sender_private_key_bytes),
            &b64(&v.recipient_public_key_base64),
            &plaintext,
        )
        .unwrap();

        let opened = open_notification(
            &key(&v.recipient_private_key_bytes),
            &b64(&v.sender_public_key_base64),
            &sealed.enc,
            &sealed.ct,
        )
        .unwrap();
        assert_eq!(opened, plaintext, "{}", v.comment);
    }
}
