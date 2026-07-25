// pattern: Functional Core

//! HPKE sealing for push notifications, and the padding arithmetic that hides plaintext
//! length from the relay and from Apple.
//!
//! The ciphersuite is **pinned**, never negotiated: DHKEM(P-256, HKDF-SHA256) +
//! HKDF-SHA256 + AES-256-GCM in RFC 9180 `mode_auth`. The pin is forced by the receiving
//! end — Apple's CryptoKit ships exactly one P-256 HPKE ciphersuite
//! (`P256_SHA256_AES_GCM_256`), so there is nothing to negotiate and no downgrade lattice
//! to defend. The protocol version lives in [`NOTIFY_INFO`] (and, redundantly, in the
//! envelope's `v` field), so a future suite change means a new info string, not a
//! negotiated parameter.
//!
//! `mode_auth` is what makes the relay a blind *courier* rather than a trusted one: the
//! recipient's open only succeeds if the sender proved possession of the pinned sender
//! private key, so a malicious relay can drop or duplicate pushes but cannot author
//! content that renders as authentic.

use hpke::{
    aead::AesGcm256, kdf::HkdfSha256, kem::DhP256HkdfSha256, Deserializable, Kem as _, OpModeR,
    OpModeS, Serializable,
};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use rand_core_os::{OsRng, UnwrapErr};

use crate::error::CryptoError;

type Kem = DhP256HkdfSha256;
type Kdf = HkdfSha256;
type Aead = AesGcm256;

/// RFC 9180 `info` for v1 notification payloads. Binds every derived key to this protocol
/// and version: a payload sealed for a different protocol can never open here, because the
/// info string is mixed into the key schedule.
pub const NOTIFY_INFO: &[u8] = b"ezpds/notify/1";

/// RFC 9180 `aad` for v1. Empty on purpose — every field a receiver must trust
/// (protocol, version, suite) is already bound through `info`, and the envelope carries no
/// cleartext field worth authenticating separately. The relay-visible envelope keys (`kid`,
/// `v`) are routing hints; a forged one causes a decryption failure, not a trust decision.
pub const NOTIFY_AAD: &[u8] = b"";

/// Uncompressed SEC1 P-256 point: `0x04` tag + 32-byte X + 32-byte Y. This is both the
/// encapsulated-key length and the public-key wire length for DHKEM(P-256).
const P256_UNCOMPRESSED_LEN: usize = 65;

/// A sealed notification: the HPKE encapsulated key and the AEAD ciphertext (tag included).
///
/// Both travel base64url-encoded in the APNs envelope's `ezpds` object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedNotification {
    /// Encapsulated key — always [`P256_UNCOMPRESSED_LEN`] bytes for this suite.
    pub enc: Vec<u8>,
    /// Ciphertext with the 16-byte AES-GCM tag appended.
    pub ct: Vec<u8>,
}

/// Seal `plaintext` to `recipient_public_key`, authenticated as `sender_private_key`.
///
/// `sender_private_key` is the raw 32-byte P-256 scalar of the instance's notification
/// sender key (the one named by `kid` in the envelope). `recipient_public_key` is the
/// device's notification public key as SEC1 bytes, compressed (33) or uncompressed (65) —
/// callers decoding a `did:key` hand us the compressed form.
pub fn seal_notification(
    sender_private_key: &[u8; 32],
    recipient_public_key: &[u8],
    plaintext: &[u8],
) -> Result<SealedNotification, CryptoError> {
    let sender_sk = private_key_from_bytes(sender_private_key)?;
    let sender_pk = Kem::sk_to_pk(&sender_sk);
    let recipient_pk = public_key_from_sec1(recipient_public_key)?;

    let (enc, ct) = hpke::single_shot_seal::<Aead, Kdf, Kem, _>(
        &OpModeS::Auth((sender_sk, sender_pk)),
        &recipient_pk,
        NOTIFY_INFO,
        plaintext,
        NOTIFY_AAD,
        // rand_core 0.9 models the OS RNG as fallible; `UnwrapErr` restores the infallible
        // `RngCore` hpke wants. A failing OS CSPRNG is not a condition we can seal through,
        // so panicking is the correct outcome — the alternative is a payload sealed under
        // degraded randomness.
        &mut UnwrapErr(OsRng),
    )
    .map_err(|_| CryptoError::Encryption("hpke seal failed".to_string()))?;

    Ok(SealedNotification {
        enc: enc.to_bytes().to_vec(),
        ct,
    })
}

/// Open a sealed notification, verifying it came from `sender_public_key`.
///
/// Every failure — malformed key, wrong sender, wrong recipient, corrupted ciphertext —
/// collapses into the same opaque [`CryptoError::Decryption`]. The caller learns only that
/// the payload did not authenticate, which is all it may act on.
pub fn open_notification(
    recipient_private_key: &[u8; 32],
    sender_public_key: &[u8],
    enc: &[u8],
    ct: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let opaque = || CryptoError::Decryption("hpke open failed".to_string());

    let recipient_sk = private_key_from_bytes(recipient_private_key).map_err(|_| opaque())?;
    let sender_pk = public_key_from_sec1(sender_public_key).map_err(|_| opaque())?;
    let encapped_key = <Kem as hpke::Kem>::EncappedKey::from_bytes(enc).map_err(|_| opaque())?;

    hpke::single_shot_open::<Aead, Kdf, Kem>(
        &OpModeR::Auth(sender_pk),
        &recipient_sk,
        &encapped_key,
        NOTIFY_INFO,
        ct,
        NOTIFY_AAD,
    )
    .map_err(|_| opaque())
}

/// Derive the uncompressed SEC1 public key for a raw 32-byte P-256 secret scalar.
///
/// Sender keys are stored as scalars; the wire and the recipient's `OpModeR::Auth` need the
/// point. Kept here so callers never re-derive it with a differently-encoded point.
pub fn public_key_for_secret(private_key: &[u8; 32]) -> Result<Vec<u8>, CryptoError> {
    let sk = private_key_from_bytes(private_key)?;
    Ok(Kem::sk_to_pk(&sk).to_bytes().to_vec())
}

fn private_key_from_bytes(bytes: &[u8; 32]) -> Result<<Kem as hpke::Kem>::PrivateKey, CryptoError> {
    <Kem as hpke::Kem>::PrivateKey::from_bytes(bytes)
        .map_err(|_| CryptoError::KeyGeneration("invalid P-256 private key".to_string()))
}

/// Accept either SEC1 encoding and normalize to the uncompressed form hpke requires.
fn public_key_from_sec1(bytes: &[u8]) -> Result<<Kem as hpke::Kem>::PublicKey, CryptoError> {
    let invalid = || CryptoError::KeyGeneration("invalid P-256 public key".to_string());

    let uncompressed = if bytes.len() == P256_UNCOMPRESSED_LEN {
        bytes.to_vec()
    } else {
        // p256 rejects off-curve and identity points, so this is a validating decode, not a
        // reformat. It rides the workspace's own p256 — the same version hpke resolves to.
        p256::PublicKey::from_sec1_bytes(bytes)
            .map_err(|_| invalid())?
            .to_encoded_point(false)
            .as_bytes()
            .to_vec()
    };

    <Kem as hpke::Kem>::PublicKey::from_bytes(&uncompressed).map_err(|_| invalid())
}

// ── Padding ───────────────────────────────────────────────────────────────────────────
//
// The relay and Apple both see the ciphertext length, and notification *length* leaks
// notification *kind* (an "agent claim pending" body is not the size of a "transfer
// complete" one). Padding quantizes it to a handful of buckets so length carries at most
// log2(3) bits instead of a fingerprint.
//
// Buckets are defined on the **serialized APNs request body**, not on the plaintext,
// because that is the only length an observer actually measures — and the mapping from
// plaintext to body length runs through base64url expansion of `enc` and `ct`, which is
// deterministic but not 1:1.

/// Serialized-body size buckets, ascending. The largest keeps headroom under
/// [`APNS_MAX_PAYLOAD_BYTES`] for the relay's own framing.
pub const PADDING_BUCKETS: [usize; 3] = [1024, 2048, 3584];

/// APNs' hard payload ceiling. A body at or above this is rejected by Apple; the relay
/// enforces the same cap defensively.
pub const APNS_MAX_PAYLOAD_BYTES: usize = 4096;

/// Bytes to add to a serialized body of `unpadded_serialized_len` so it lands exactly on the
/// smallest bucket that fits.
///
/// Returns `None` when even the largest bucket won't fit — the payload is unsendable and the
/// caller must shrink it rather than push an unpadded body whose length leaks.
pub fn pad_len_for_bucket(unpadded_serialized_len: usize) -> Option<usize> {
    PADDING_BUCKETS
        .iter()
        .find(|&&bucket| bucket >= unpadded_serialized_len)
        .map(|&bucket| bucket - unpadded_serialized_len)
}

/// Number of `0x20` bytes to append to the plaintext's `pad` field so the serialized body
/// lands on its bucket.
///
/// This is the serialized-space budget from [`pad_len_for_bucket`] pulled back through
/// base64url: `unpadded_ct_len` bytes of ciphertext encode to `base64url_len(ct)` characters,
/// and each additional plaintext byte grows that by 1 or 2. The expansion therefore cannot
/// hit every budget exactly (deltas of 1, 5, 9, … are unreachable), so this returns the
/// largest pad that does not overshoot — the body lands on the bucket or at most one byte
/// under it, which quantizes length just as well as an exact hit.
///
/// `unpadded_ct_len` is the raw ciphertext length (AEAD tag included) for the plaintext with
/// an empty `pad`; `unpadded_serialized_len` is the full serialized body for that same
/// payload. Returns `None` on the same unsendable condition as [`pad_len_for_bucket`].
pub fn plaintext_pad_len(unpadded_ct_len: usize, unpadded_serialized_len: usize) -> Option<usize> {
    let budget = pad_len_for_bucket(unpadded_serialized_len)?;
    let base = base64url_len(unpadded_ct_len);

    // Expansion is monotone at 4 characters per 3 bytes, so the answer is within
    // budget * 3 / 4 ..= budget; walk down from the ceiling rather than search.
    let mut pad = budget;
    while pad > 0 && base64url_len(unpadded_ct_len + pad) - base > budget {
        pad -= 1;
    }
    Some(pad)
}

/// Length of `n` bytes encoded as unpadded base64url (the `enc`/`ct` encoding in the
/// envelope): 4 characters per 3-byte group, with a 2- or 3-character tail.
pub fn base64url_len(n: usize) -> usize {
    n / 3 * 4
        + match n % 3 {
            0 => 0,
            1 => 2,
            _ => 3,
        }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keypair(seed: &[u8; 32]) -> ([u8; 32], Vec<u8>) {
        let (sk, pk) = <Kem as hpke::Kem>::derive_keypair(seed);
        let mut sk_bytes = [0u8; 32];
        sk_bytes.copy_from_slice(&sk.to_bytes());
        (sk_bytes, pk.to_bytes().to_vec())
    }

    #[test]
    fn round_trips_with_the_pinned_suite() {
        let (sender_sk, sender_pk) = keypair(&[1u8; 32]);
        let (recipient_sk, recipient_pk) = keypair(&[2u8; 32]);

        let sealed = seal_notification(&sender_sk, &recipient_pk, b"claim pending").unwrap();
        assert_eq!(sealed.enc.len(), P256_UNCOMPRESSED_LEN);
        assert_eq!(sealed.ct.len(), b"claim pending".len() + 16);

        let opened = open_notification(&recipient_sk, &sender_pk, &sealed.enc, &sealed.ct).unwrap();
        assert_eq!(opened, b"claim pending");
    }

    #[test]
    fn accepts_a_compressed_recipient_key() {
        let (sender_sk, sender_pk) = keypair(&[3u8; 32]);
        let (recipient_sk, recipient_pk) = keypair(&[4u8; 32]);
        let compressed = p256::PublicKey::from_sec1_bytes(&recipient_pk)
            .unwrap()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec();
        assert_eq!(compressed.len(), 33);

        let sealed = seal_notification(&sender_sk, &compressed, b"hi").unwrap();
        assert_eq!(
            open_notification(&recipient_sk, &sender_pk, &sealed.enc, &sealed.ct).unwrap(),
            b"hi"
        );
    }

    #[test]
    fn wrong_sender_key_fails_opaquely() {
        let (sender_sk, _) = keypair(&[5u8; 32]);
        let (_, impostor_pk) = keypair(&[6u8; 32]);
        let (recipient_sk, recipient_pk) = keypair(&[7u8; 32]);

        let sealed = seal_notification(&sender_sk, &recipient_pk, b"payload").unwrap();
        let err =
            open_notification(&recipient_sk, &impostor_pk, &sealed.enc, &sealed.ct).unwrap_err();
        assert_eq!(err.to_string(), "decryption failed: hpke open failed");
    }

    #[test]
    fn wrong_recipient_key_fails_opaquely() {
        let (sender_sk, sender_pk) = keypair(&[8u8; 32]);
        let (_, recipient_pk) = keypair(&[9u8; 32]);
        let (other_sk, _) = keypair(&[10u8; 32]);

        let sealed = seal_notification(&sender_sk, &recipient_pk, b"payload").unwrap();
        assert!(open_notification(&other_sk, &sender_pk, &sealed.enc, &sealed.ct).is_err());
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let (sender_sk, sender_pk) = keypair(&[11u8; 32]);
        let (recipient_sk, recipient_pk) = keypair(&[12u8; 32]);

        let mut sealed = seal_notification(&sender_sk, &recipient_pk, b"payload").unwrap();
        sealed.ct[0] ^= 0x01;
        assert!(open_notification(&recipient_sk, &sender_pk, &sealed.enc, &sealed.ct).is_err());
    }

    #[test]
    fn malformed_inputs_fail_rather_than_panic() {
        let (sender_sk, sender_pk) = keypair(&[13u8; 32]);
        let (recipient_sk, recipient_pk) = keypair(&[14u8; 32]);
        let sealed = seal_notification(&sender_sk, &recipient_pk, b"payload").unwrap();

        assert!(seal_notification(&sender_sk, &[0u8; 65], b"x").is_err());
        assert!(seal_notification(&[0u8; 32], &recipient_pk, b"x").is_err());
        assert!(open_notification(&recipient_sk, &sender_pk, &[], &sealed.ct).is_err());
        assert!(open_notification(&recipient_sk, &[], &sealed.enc, &sealed.ct).is_err());
        assert!(open_notification(&recipient_sk, &sender_pk, &sealed.enc, &[]).is_err());
    }

    #[test]
    fn every_seal_uses_a_fresh_encapsulated_key() {
        let (sender_sk, _) = keypair(&[15u8; 32]);
        let (_, recipient_pk) = keypair(&[16u8; 32]);

        let a = seal_notification(&sender_sk, &recipient_pk, b"payload").unwrap();
        let b = seal_notification(&sender_sk, &recipient_pk, b"payload").unwrap();
        assert_ne!(a.enc, b.enc);
        assert_ne!(a.ct, b.ct);
    }

    #[test]
    fn public_key_for_secret_matches_the_kem() {
        let (sk, pk) = keypair(&[17u8; 32]);
        assert_eq!(public_key_for_secret(&sk).unwrap(), pk);
    }

    #[test]
    fn padding_table() {
        // Smallest bucket that fits, and the exact bucket boundaries themselves.
        assert_eq!(pad_len_for_bucket(0), Some(1024));
        assert_eq!(pad_len_for_bucket(1), Some(1023));
        assert_eq!(pad_len_for_bucket(1024), Some(0));
        assert_eq!(pad_len_for_bucket(1025), Some(1023));
        assert_eq!(pad_len_for_bucket(2048), Some(0));
        assert_eq!(pad_len_for_bucket(2049), Some(1535));
        assert_eq!(pad_len_for_bucket(3583), Some(1));
        assert_eq!(pad_len_for_bucket(3584), Some(0));

        // Above the largest bucket the payload is unsendable — including everything between
        // the top bucket and APNs' own 4096 ceiling, and the exact-4096 boundary.
        assert_eq!(pad_len_for_bucket(3585), None);
        assert_eq!(pad_len_for_bucket(APNS_MAX_PAYLOAD_BYTES - 1), None);
        assert_eq!(pad_len_for_bucket(APNS_MAX_PAYLOAD_BYTES), None);
        assert_eq!(pad_len_for_bucket(APNS_MAX_PAYLOAD_BYTES + 1), None);

        // Padding never pushes a body past APNs' cap.
        assert!(PADDING_BUCKETS.iter().all(|&b| b < APNS_MAX_PAYLOAD_BYTES));
    }

    #[test]
    fn base64url_len_matches_the_encoder() {
        use base64::Engine;
        for n in 0..200 {
            let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(vec![0u8; n]);
            assert_eq!(base64url_len(n), encoded.len(), "n = {n}");
        }
        // The `enc` field is always a 65-byte point → 87 characters.
        assert_eq!(base64url_len(P256_UNCOMPRESSED_LEN), 87);
    }

    #[test]
    fn plaintext_pad_len_lands_on_the_bucket_without_overshooting() {
        for ct_len in [64usize, 65, 66, 100, 333] {
            for serialized in [200usize, 1024, 1500, 2048, 3000] {
                let pad = plaintext_pad_len(ct_len, serialized).unwrap();
                let grown = serialized + base64url_len(ct_len + pad) - base64url_len(ct_len);
                let bucket = *PADDING_BUCKETS.iter().find(|&&b| b >= serialized).unwrap();
                // Never overshoot the bucket, and land within one byte of it (base64's
                // 3-bytes-to-4-characters step makes some exact hits unreachable).
                assert!(grown <= bucket, "ct={ct_len} serialized={serialized}");
                assert!(bucket - grown <= 1, "ct={ct_len} serialized={serialized}");
            }
        }

        // Already on a bucket → no padding; unsendable → None.
        assert_eq!(plaintext_pad_len(100, 1024), Some(0));
        assert_eq!(plaintext_pad_len(100, 3585), None);
    }
}
