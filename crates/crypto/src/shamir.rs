use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::mnemonic::{bytes_to_words, words_to_bytes};
use crate::CryptoError;

/// A single Shamir secret share for a 32-byte secret.
///
/// `data` contains secret material and is zeroized on drop.
pub struct ShamirShare {
    /// Share index: 1, 2, or 3. Not secret.
    pub index: u8,
    /// 32 bytes of share data. Zeroized on drop.
    pub data: Zeroizing<[u8; 32]>,
}

/// Split a 32-byte secret into 3 Shamir shares using a 2-of-3 threshold.
///
/// Any 2 of the 3 returned shares can reconstruct the original secret via
/// [`combine_shares`]. A single share reveals nothing about the secret
/// (information-theoretic security).
///
/// Uses GF(2^8) arithmetic with the AES irreducible polynomial
/// p(x) = x^8 + x^4 + x^3 + x + 1 (0x11b).
pub fn split_secret(secret: &[u8; 32]) -> Result<[ShamirShare; 3], CryptoError> {
    let mut coeffs = Zeroizing::new([0u8; 32]);
    OsRng
        .try_fill_bytes(coeffs.as_mut())
        .map_err(|e| CryptoError::SecretSharing(format!("OS RNG unavailable: {e}")))?;

    let mut s1 = Zeroizing::new([0u8; 32]);
    let mut s2 = Zeroizing::new([0u8; 32]);
    let mut s3 = Zeroizing::new([0u8; 32]);

    // Polynomial: f(x) = secret[i] + coeffs[i]·x in GF(2^8).
    // f(0) = secret[i]. Shares are f(1), f(2), f(3).
    //
    // Secret-bearing coefficient bytes are in the first argument of gf_mul.
    // The polynomial reduction inside gf_mul is branchless (mask-based), so
    // bit patterns of the coefficients are not observable through branch
    // timing. The `if b & 1` branch in gf_mul is on the public share index.
    for i in 0..32 {
        let s = secret[i];
        let a = coeffs[i];
        s1[i] = gf_add(s, gf_mul(a, 1));
        s2[i] = gf_add(s, gf_mul(a, 2));
        s3[i] = gf_add(s, gf_mul(a, 3));
    }

    Ok([
        ShamirShare { index: 1, data: s1 },
        ShamirShare { index: 2, data: s2 },
        ShamirShare { index: 3, data: s3 },
    ])
}

/// Reconstruct the original secret from any 2 Shamir shares.
///
/// The two shares must have distinct indices in the range [1, 3].
/// Returns [`CryptoError::SecretReconstruction`] for invalid input.
///
/// # Algorithm
///
/// Lagrange interpolation at x=0 in GF(2^8). For two points (x_a, y_a)
/// and (x_b, y_b) on the degree-1 polynomial f(x) = secret + coeff·x:
///
/// ```text
/// Standard Lagrange:  f(0) = y_a · (0−x_b)/(x_a−x_b) + y_b · (0−x_a)/(x_b−x_a)
/// In GF(2^8) (−x = x):  f(0) = y_a · x_b/(x_a⊕x_b) ⊕ y_b · x_a/(x_a⊕x_b)
/// ```
pub fn combine_shares(
    a: &ShamirShare,
    b: &ShamirShare,
) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    if a.index == 0 || a.index > 3 || b.index == 0 || b.index > 3 {
        return Err(CryptoError::SecretReconstruction(
            "share index must be in [1, 3]".into(),
        ));
    }
    if a.index == b.index {
        return Err(CryptoError::SecretReconstruction(
            "shares must have distinct indices".into(),
        ));
    }

    let x_a = a.index;
    let x_b = b.index;
    // x_a ⊕ x_b is guaranteed nonzero since x_a ≠ x_b; gf_div cannot fail here.
    let denom = gf_add(x_a, x_b);
    // Lagrange basis values at x=0, derived from public indices — timing is fine.
    let l_a = gf_div(x_b, denom)?;
    let l_b = gf_div(x_a, denom)?;

    let mut secret = Zeroizing::new([0u8; 32]);
    for i in 0..32 {
        // Secret share bytes are in the first argument of gf_mul (branchless reduction).
        secret[i] = gf_add(gf_mul(a.data[i], l_a), gf_mul(b.data[i], l_b));
    }
    Ok(secret)
}

// ── Share envelope v2 ─────────────────────────────────────────────────────────
//
// A bare 32-byte share is not self-describing: nothing in it says which generation of shares it
// belongs to or which index it is, so combining a share from one split with a share from a *later*
// re-split would silently reconstruct a wrong-but-valid-looking 32 bytes. The v2 envelope makes a
// share self-describing:
//
//   version(1B) || set_id(4B, big-endian) || index(1B) || payload(32B) || checksum(4B)
//
// where `checksum` is the first 4 bytes of SHA-256 over the preceding 38 bytes. `set_id` ties the
// three shares of one split together; `combine_envelopes` refuses to combine shares whose `set_id`
// differs. The index is carried in the envelope, so a caller never has to track "which share is
// this" out of band.

/// Current share-envelope version. Bumped only on a breaking format change.
pub const SHARE_ENVELOPE_VERSION: u8 = 2;

/// Total encoded length of a share envelope in bytes.
pub const SHARE_ENVELOPE_LEN: usize = 42;

const ENVELOPE_PAYLOAD_LEN: usize = 32;
const ENVELOPE_CHECKSUM_LEN: usize = 4;
/// Length of the bytes the checksum covers: everything before the checksum (version + set_id +
/// index + payload).
const ENVELOPE_PREIMAGE_LEN: usize = SHARE_ENVELOPE_LEN - ENVELOPE_CHECKSUM_LEN; // 38

/// A self-describing Shamir share (version 2).
///
/// Wraps a raw [`ShamirShare`] payload with the metadata needed to combine it safely: a `set_id`
/// that identifies the split it came from and the share `index`. The `payload` is secret material
/// and is zeroized on drop.
pub struct ShareEnvelope {
    /// Envelope format version. Always [`SHARE_ENVELOPE_VERSION`] for envelopes this crate builds.
    pub version: u8,
    /// Identifies the split (generation) these three shares belong to. Shares with differing
    /// `set_id` values must never be combined.
    pub set_id: u32,
    /// Share index in `[1, 3]`. Not secret.
    pub index: u8,
    /// 32 bytes of Shamir share data. Zeroized on drop.
    pub payload: Zeroizing<[u8; 32]>,
}

// Redacts the secret payload — a `ShareEnvelope` carries share material that must never land in a
// log or panic message. Only the non-secret metadata is shown.
impl std::fmt::Debug for ShareEnvelope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ShareEnvelope")
            .field("version", &self.version)
            .field("set_id", &self.set_id)
            .field("index", &self.index)
            .field("payload", &"<redacted>")
            .finish()
    }
}

impl ShareEnvelope {
    /// Wrap a raw [`ShamirShare`] into a versioned envelope tied to `set_id`.
    fn from_share(set_id: u32, share: &ShamirShare) -> Self {
        ShareEnvelope {
            version: SHARE_ENVELOPE_VERSION,
            set_id,
            index: share.index,
            payload: share.data.clone(),
        }
    }

    /// The bytes the checksum is computed over: `version || set_id || index || payload`.
    fn preimage(&self) -> Zeroizing<[u8; ENVELOPE_PREIMAGE_LEN]> {
        let mut buf = Zeroizing::new([0u8; ENVELOPE_PREIMAGE_LEN]);
        buf[0] = self.version;
        buf[1..5].copy_from_slice(&self.set_id.to_be_bytes());
        buf[5] = self.index;
        buf[6..ENVELOPE_PREIMAGE_LEN].copy_from_slice(self.payload.as_slice());
        buf
    }

    /// Serialize to the full 42-byte envelope, appending a freshly computed checksum.
    pub fn to_bytes(&self) -> Zeroizing<[u8; SHARE_ENVELOPE_LEN]> {
        let preimage = self.preimage();
        let checksum = envelope_checksum(preimage.as_slice());
        let mut out = Zeroizing::new([0u8; SHARE_ENVELOPE_LEN]);
        out[..ENVELOPE_PREIMAGE_LEN].copy_from_slice(preimage.as_slice());
        out[ENVELOPE_PREIMAGE_LEN..].copy_from_slice(&checksum);
        out
    }

    /// Parse a 42-byte envelope, validating length, version, and checksum.
    ///
    /// # Errors
    /// - [`CryptoError::ShareFormat`] if the length or index is invalid.
    /// - [`CryptoError::ShareVersion`] if the version byte is not [`SHARE_ENVELOPE_VERSION`].
    /// - [`CryptoError::ShareChecksum`] if the trailing checksum does not match the body.
    ///
    /// Version is checked before the checksum so a future-version share reports a version error
    /// (actionable: "upgrade / use the right tool") rather than a generic corruption error.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != SHARE_ENVELOPE_LEN {
            return Err(CryptoError::ShareFormat(format!(
                "expected {SHARE_ENVELOPE_LEN} bytes, got {}",
                bytes.len()
            )));
        }

        let version = bytes[0];
        if version != SHARE_ENVELOPE_VERSION {
            return Err(CryptoError::ShareVersion(format!(
                "got version {version}, expected {SHARE_ENVELOPE_VERSION}"
            )));
        }

        let (preimage, checksum) = bytes.split_at(ENVELOPE_PREIMAGE_LEN);
        let expected = envelope_checksum(preimage);
        // Constant-time-ish is unnecessary here: the checksum is public integrity metadata, not a
        // secret. A plain compare is fine.
        if checksum != expected {
            return Err(CryptoError::ShareChecksum(
                "trailing checksum does not match envelope body".to_string(),
            ));
        }

        let set_id = u32::from_be_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]);
        let index = bytes[5];
        if index == 0 || index > 3 {
            return Err(CryptoError::ShareFormat(format!(
                "share index must be in [1, 3], got {index}"
            )));
        }

        let mut payload = Zeroizing::new([0u8; ENVELOPE_PAYLOAD_LEN]);
        payload.copy_from_slice(&bytes[6..ENVELOPE_PREIMAGE_LEN]);

        Ok(ShareEnvelope {
            version,
            set_id,
            index,
            payload,
        })
    }

    /// Encode the envelope as an uppercase, unpadded base32 string (RFC 4648).
    ///
    /// Uppercase base32 uses only characters in QR codes' alphanumeric mode, keeping machine shares
    /// (Shares 1 and 2) compact when rendered as a QR code.
    pub fn encode_share(&self) -> String {
        data_encoding::BASE32_NOPAD.encode(self.to_bytes().as_slice())
    }

    /// Decode a share from its base32 string form (as produced by [`encode_share`]).
    ///
    /// Surrounding whitespace is ignored and lowercase input is accepted. Returns the same
    /// distinct errors as [`from_bytes`], plus [`CryptoError::ShareFormat`] for non-base32 input.
    ///
    /// [`encode_share`]: ShareEnvelope::encode_share
    /// [`from_bytes`]: ShareEnvelope::from_bytes
    pub fn decode_share(encoded: &str) -> Result<Self, CryptoError> {
        let normalized: String = encoded
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect::<String>()
            .to_ascii_uppercase();
        let bytes = data_encoding::BASE32_NOPAD
            .decode(normalized.as_bytes())
            .map_err(|e| CryptoError::ShareFormat(format!("invalid base32: {e}")))?;
        Self::from_bytes(&bytes)
    }

    /// Render the envelope as a BIP-39-style mnemonic phrase for the human-custody share (Share 3).
    ///
    /// The whole 42-byte envelope — including its checksum — is encoded, so a phrase is
    /// self-describing exactly like the base32 form and can be combined with a machine share.
    pub fn encode_share_words(&self) -> String {
        bytes_to_words(self.to_bytes().as_slice())
    }

    /// Parse a mnemonic phrase produced by [`encode_share_words`] back into an envelope.
    ///
    /// Returns [`CryptoError::ShareFormat`] for an unknown word, and the same version/checksum
    /// errors as [`from_bytes`] once the words decode to bytes.
    ///
    /// [`encode_share_words`]: ShareEnvelope::encode_share_words
    /// [`from_bytes`]: ShareEnvelope::from_bytes
    pub fn decode_share_words(phrase: &str) -> Result<Self, CryptoError> {
        let bytes = words_to_bytes(phrase)?;
        Self::from_bytes(&bytes)
    }
}

/// First 4 bytes of SHA-256 over the envelope preimage.
fn envelope_checksum(preimage: &[u8]) -> [u8; ENVELOPE_CHECKSUM_LEN] {
    let digest = Sha256::digest(preimage);
    let mut checksum = [0u8; ENVELOPE_CHECKSUM_LEN];
    checksum.copy_from_slice(&digest[..ENVELOPE_CHECKSUM_LEN]);
    checksum
}

/// Split a 32-byte secret into 3 self-describing share envelopes tied to `set_id`.
///
/// The GF(2^8) split is identical to [`split_secret`]; each resulting share is wrapped in a v2
/// envelope carrying `set_id` and its index. The caller supplies `set_id` (typically a fresh
/// random value per split) so the three envelopes of one generation can be told apart from a later
/// re-split's — see [`combine_envelopes`].
pub fn split_secret_into_envelopes(
    secret: &[u8; 32],
    set_id: u32,
) -> Result<[ShareEnvelope; 3], CryptoError> {
    let shares = split_secret(secret)?;
    Ok([
        ShareEnvelope::from_share(set_id, &shares[0]),
        ShareEnvelope::from_share(set_id, &shares[1]),
        ShareEnvelope::from_share(set_id, &shares[2]),
    ])
}

/// Reconstruct the secret from two share envelopes, refusing cross-generation combines.
///
/// Unlike [`combine_shares`], the share indices come from the envelopes themselves, and the two
/// envelopes' `set_id` values **must match** — a mismatch returns [`CryptoError::SecretReconstruction`]
/// loudly rather than silently interpolating two unrelated shares into a wrong-but-valid-looking
/// secret. Distinct indices in `[1, 3]` are still required (enforced by [`combine_shares`]).
pub fn combine_envelopes(
    a: &ShareEnvelope,
    b: &ShareEnvelope,
) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    if a.set_id != b.set_id {
        return Err(CryptoError::SecretReconstruction(format!(
            "share set_id mismatch ({} != {}): these shares are from different generations and must not be combined",
            a.set_id, b.set_id
        )));
    }

    let share_a = ShamirShare {
        index: a.index,
        data: a.payload.clone(),
    };
    let share_b = ShamirShare {
        index: b.index,
        data: b.payload.clone(),
    };
    combine_shares(&share_a, &share_b)
}

// ── GF(2^8) arithmetic ────────────────────────────────────────────────────────

/// GF(2^8) addition — XOR in any characteristic-2 field.
fn gf_add(a: u8, b: u8) -> u8 {
    a ^ b
}

/// GF(2^8) multiplication using the AES irreducible polynomial
/// p(x) = x^8 + x^4 + x^3 + x + 1 (represented as 0x11b; low byte 0x1b).
///
/// Uses the double-and-add algorithm (Russian peasant), processing 8 bits of
/// `b` LSB-first. The polynomial reduction is **branchless**: an arithmetic
/// right-shift produces a mask that selects the reduction constant without
/// branching on bits of `a`. The `if b & 1` branch is on `b` (the public
/// share index or Lagrange coefficient), not on secret data.
///
/// By convention, secret values are always passed as the **first argument**
/// so that branching on `b` never leaks secret bit patterns.
fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut result = 0u8;
    for _ in 0..8 {
        if b & 1 != 0 {
            result ^= a;
        }
        // Branchless GF(2^8) doubling. Arithmetic right-shift of the signed
        // reinterpretation of `a` fills with the high bit, producing 0xFF when
        // bit 7 is set and 0x00 otherwise. The mask selects the reduction
        // constant (0x1b = low byte of 0x11b) without branching on `a`.
        let mask = (a as i8 >> 7) as u8;
        a = (a << 1) ^ (mask & 0x1b);
        b >>= 1;
    }
    result
}

/// Multiplicative inverse in GF(2^8) via Fermat's little theorem:
/// a^(2^8 − 2) = a^254 = a^(−1) (since |GF(2^8)*| = 255).
///
/// Computed via binary exponentiation (square-and-multiply) on top of `gf_mul`.
fn gf_inv(a: u8) -> Result<u8, CryptoError> {
    if a == 0 {
        return Err(CryptoError::SecretReconstruction(
            "GF(2^8) inverse of 0 is undefined".into(),
        ));
    }
    // a^254 by binary exponentiation (254 = 0b11111110).
    let mut result = 1u8;
    let mut base = a;
    let mut exp = 254u8;
    while exp > 0 {
        if exp & 1 != 0 {
            result = gf_mul(result, base);
        }
        base = gf_mul(base, base);
        exp >>= 1;
    }
    Ok(result)
}

/// GF(2^8) division: a / b = a · b^(−1).
fn gf_div(a: u8, b: u8) -> Result<u8, CryptoError> {
    Ok(gf_mul(a, gf_inv(b)?))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Splitting a 32-byte secret produces 3 shares ──────────────────────────

    #[test]
    fn split_shares_have_correct_indices() {
        let secret = [0x42_u8; 32];
        let shares = split_secret(&secret).unwrap();
        assert_eq!(shares[0].index, 1);
        assert_eq!(shares[1].index, 2);
        assert_eq!(shares[2].index, 3);
    }

    #[test]
    fn split_shares_are_32_bytes() {
        let secret = [0x42_u8; 32];
        let shares = split_secret(&secret).unwrap();
        for share in &shares {
            assert_eq!(share.data.len(), 32);
        }
    }

    // ── Any 2 shares reconstruct the original secret ──────────────────────────

    #[test]
    fn combine_shares_1_and_2_reconstructs_secret() {
        let secret = [0x42_u8; 32];
        let shares = split_secret(&secret).unwrap();
        let recovered = combine_shares(&shares[0], &shares[1]).unwrap();
        assert_eq!(*recovered, secret);
    }

    #[test]
    fn combine_shares_1_and_3_reconstructs_secret() {
        let secret = [0x42_u8; 32];
        let shares = split_secret(&secret).unwrap();
        let recovered = combine_shares(&shares[0], &shares[2]).unwrap();
        assert_eq!(*recovered, secret);
    }

    #[test]
    fn combine_shares_2_and_3_reconstructs_secret() {
        let secret = [0x42_u8; 32];
        let shares = split_secret(&secret).unwrap();
        let recovered = combine_shares(&shares[1], &shares[2]).unwrap();
        assert_eq!(*recovered, secret);
    }

    #[test]
    fn combine_is_commutative() {
        let secret = [0xAB_u8; 32];
        let shares = split_secret(&secret).unwrap();
        let r1 = combine_shares(&shares[0], &shares[1]).unwrap();
        let r2 = combine_shares(&shares[1], &shares[0]).unwrap();
        assert_eq!(*r1, *r2);
    }

    #[test]
    fn round_trip_all_zeros() {
        let secret = [0x00_u8; 32];
        let shares = split_secret(&secret).unwrap();
        let recovered = combine_shares(&shares[0], &shares[1]).unwrap();
        assert_eq!(*recovered, secret);
    }

    #[test]
    fn round_trip_all_ones() {
        let secret = [0xFF_u8; 32];
        let shares = split_secret(&secret).unwrap();
        let recovered = combine_shares(&shares[0], &shares[1]).unwrap();
        assert_eq!(*recovered, secret);
    }

    /// Integration test: all three pair combinations reconstruct the same secret.
    #[test]
    fn round_trip_all_pairs() {
        let secret: [u8; 32] = core::array::from_fn(|i| (i * 17 + 3) as u8);
        let shares = split_secret(&secret).unwrap();
        for i in 0..3 {
            for j in (i + 1)..3 {
                let recovered = combine_shares(&shares[i], &shares[j]).unwrap();
                assert_eq!(*recovered, secret, "pair ({i}, {j}) failed to reconstruct");
            }
        }
    }

    // ── Single share reveals nothing ───────────────────────────────────────────

    /// Sanity check: with overwhelming probability, share data ≠ plaintext.
    /// (Not a proof of information-theoretic security; the math guarantees that.)
    #[test]
    fn shares_are_not_plaintext() {
        let secret = [0x42_u8; 32];
        let shares = split_secret(&secret).unwrap();
        // P(all three shares equal secret) ≈ 0 (requires coeffs[i]=0 for all i).
        assert!(
            *shares[0].data != secret || *shares[1].data != secret || *shares[2].data != secret,
            "at least one share must differ from the plaintext secret"
        );
    }

    // ── Error handling ────────────────────────────────────────────────────────

    #[test]
    fn combine_duplicate_indices_fails() {
        let secret = [0x42_u8; 32];
        let shares = split_secret(&secret).unwrap();
        let result = combine_shares(&shares[0], &shares[0]);
        assert!(
            matches!(result, Err(CryptoError::SecretReconstruction(_))),
            "expected SecretReconstruction for duplicate indices"
        );
    }

    #[test]
    fn combine_with_index_zero_fails() {
        let zero_share = ShamirShare {
            index: 0,
            data: Zeroizing::new([0u8; 32]),
        };
        let shares = split_secret(&[0x42_u8; 32]).unwrap();
        // Both argument positions must be guarded.
        assert!(matches!(
            combine_shares(&zero_share, &shares[0]),
            Err(CryptoError::SecretReconstruction(_))
        ));
        assert!(matches!(
            combine_shares(&shares[0], &zero_share),
            Err(CryptoError::SecretReconstruction(_))
        ));
    }

    #[test]
    fn combine_with_index_out_of_range_fails() {
        let bad_share = ShamirShare {
            index: 4,
            data: Zeroizing::new([0u8; 32]),
        };
        let shares = split_secret(&[0x42_u8; 32]).unwrap();
        // Both argument positions must be guarded.
        assert!(matches!(
            combine_shares(&bad_share, &shares[0]),
            Err(CryptoError::SecretReconstruction(_))
        ));
        assert!(matches!(
            combine_shares(&shares[0], &bad_share),
            Err(CryptoError::SecretReconstruction(_))
        ));
    }

    // ── GF(2^8) arithmetic invariants ────────────────────────────────────────

    #[test]
    fn gf_mul_by_zero_is_zero() {
        for a in 0_u8..=255 {
            assert_eq!(gf_mul(a, 0), 0, "gf_mul({a}, 0) must be 0");
            assert_eq!(gf_mul(0, a), 0, "gf_mul(0, {a}) must be 0");
        }
    }

    #[test]
    fn gf_mul_by_one_is_identity() {
        for a in 0_u8..=255 {
            assert_eq!(gf_mul(a, 1), a, "gf_mul({a}, 1) must equal {a}");
            assert_eq!(gf_mul(1, a), a, "gf_mul(1, {a}) must equal {a}");
        }
    }

    #[test]
    fn gf_mul_is_commutative() {
        for a in 0_u8..=255 {
            for b in 0_u8..=255 {
                assert_eq!(
                    gf_mul(a, b),
                    gf_mul(b, a),
                    "gf_mul({a:#04x}, {b:#04x}) not commutative"
                );
            }
        }
    }

    /// Every non-zero element has a multiplicative inverse: a · a^(−1) = 1.
    #[test]
    fn gf_inv_produces_correct_inverse() {
        for a in 1_u8..=255 {
            let inv = gf_inv(a).unwrap();
            assert_eq!(
                gf_mul(a, inv),
                1,
                "a={a:#04x}, inv={inv:#04x}: a·inv must equal 1"
            );
        }
    }

    #[test]
    fn gf_inv_of_zero_fails() {
        assert!(matches!(
            gf_inv(0),
            Err(CryptoError::SecretReconstruction(_))
        ));
    }

    // ── Share envelope v2 ─────────────────────────────────────────────────────

    #[test]
    fn envelope_encodes_to_expected_length() {
        let env = split_secret_into_envelopes(&[0x42_u8; 32], 0xDEADBEEF).unwrap();
        assert_eq!(env[0].to_bytes().len(), SHARE_ENVELOPE_LEN);
        // base32(42 bytes) with no padding is ceil(42 * 8 / 5) = 68 chars.
        assert_eq!(env[0].encode_share().len(), 68);
    }

    #[test]
    fn envelope_carries_version_setid_index() {
        let set_id = 0x01020304;
        let env = split_secret_into_envelopes(&[0xAB_u8; 32], set_id).unwrap();
        for (i, e) in env.iter().enumerate() {
            assert_eq!(e.version, SHARE_ENVELOPE_VERSION);
            assert_eq!(e.set_id, set_id);
            assert_eq!(e.index, (i as u8) + 1);
        }
    }

    #[test]
    fn envelope_base32_round_trip() {
        let env = split_secret_into_envelopes(&[0x11_u8; 32], 7).unwrap();
        for e in &env {
            let encoded = e.encode_share();
            let decoded = ShareEnvelope::decode_share(&encoded).unwrap();
            assert_eq!(decoded.version, e.version);
            assert_eq!(decoded.set_id, e.set_id);
            assert_eq!(decoded.index, e.index);
            assert_eq!(*decoded.payload, *e.payload);
        }
    }

    #[test]
    fn envelope_words_round_trip() {
        // Share 3 is the human-custody share rendered as a mnemonic phrase.
        let env = split_secret_into_envelopes(&[0x5A_u8; 32], 42).unwrap();
        let share3 = &env[2];
        let phrase = share3.encode_share_words();
        // 42 bytes → 42 words.
        assert_eq!(phrase.split_whitespace().count(), SHARE_ENVELOPE_LEN);
        let decoded = ShareEnvelope::decode_share_words(&phrase).unwrap();
        assert_eq!(decoded.index, 3);
        assert_eq!(decoded.set_id, 42);
        assert_eq!(*decoded.payload, *share3.payload);
    }

    #[test]
    fn envelope_decode_is_whitespace_and_case_tolerant() {
        let env = split_secret_into_envelopes(&[0x33_u8; 32], 99).unwrap();
        let encoded = env[0].encode_share();
        let messy = format!("  {}  ", encoded.to_lowercase());
        let decoded = ShareEnvelope::decode_share(&messy).unwrap();
        assert_eq!(*decoded.payload, *env[0].payload);
    }

    #[test]
    fn split_combine_via_envelopes_all_index_pairs() {
        let secret: [u8; 32] = core::array::from_fn(|i| (i * 31 + 7) as u8);
        let env = split_secret_into_envelopes(&secret, 12345).unwrap();
        for i in 0..3 {
            for j in (i + 1)..3 {
                let recovered = combine_envelopes(&env[i], &env[j]).unwrap();
                assert_eq!(*recovered, secret, "pair ({i}, {j}) failed via envelopes");
            }
        }
    }

    #[test]
    fn split_combine_via_base32_then_words() {
        // Full path: split → serialize shares 1/2 (base32) + share 3 (words) → decode → combine.
        let secret: [u8; 32] = core::array::from_fn(|i| (i * 13 + 5) as u8);
        let env = split_secret_into_envelopes(&secret, 0xABCD1234).unwrap();
        let share1 = ShareEnvelope::decode_share(&env[0].encode_share()).unwrap();
        let share3 = ShareEnvelope::decode_share_words(&env[2].encode_share_words()).unwrap();
        let recovered = combine_envelopes(&share1, &share3).unwrap();
        assert_eq!(*recovered, secret);
    }

    #[test]
    fn combine_across_set_ids_fails_loudly() {
        let secret = [0x42_u8; 32];
        let gen_a = split_secret_into_envelopes(&secret, 1).unwrap();
        let gen_b = split_secret_into_envelopes(&secret, 2).unwrap();
        // Two shares that would each be individually valid but come from different generations.
        let result = combine_envelopes(&gen_a[0], &gen_b[1]);
        assert!(
            matches!(result, Err(CryptoError::SecretReconstruction(_))),
            "cross-set_id combine must fail loudly, got {result:?}"
        );
    }

    #[test]
    fn corrupted_checksum_fails_before_combine() {
        let env = split_secret_into_envelopes(&[0x42_u8; 32], 55).unwrap();
        let mut bytes = *env[0].to_bytes();
        // Flip a bit in the last (checksum) byte.
        bytes[SHARE_ENVELOPE_LEN - 1] ^= 0x01;
        let result = ShareEnvelope::from_bytes(&bytes);
        assert!(
            matches!(result, Err(CryptoError::ShareChecksum(_))),
            "corrupted checksum must be a distinct ShareChecksum error, got {result:?}"
        );
    }

    #[test]
    fn corrupted_payload_fails_checksum() {
        let env = split_secret_into_envelopes(&[0x42_u8; 32], 55).unwrap();
        let mut bytes = *env[0].to_bytes();
        // Flip a bit in the payload; the checksum no longer matches.
        bytes[10] ^= 0x80;
        let result = ShareEnvelope::from_bytes(&bytes);
        assert!(matches!(result, Err(CryptoError::ShareChecksum(_))));
    }

    #[test]
    fn wrong_version_is_distinct_error() {
        let env = split_secret_into_envelopes(&[0x42_u8; 32], 55).unwrap();
        // Rebuild the envelope with a bumped version so the checksum stays valid — this isolates
        // the version check from the checksum check.
        let future = ShareEnvelope {
            version: SHARE_ENVELOPE_VERSION + 1,
            set_id: env[0].set_id,
            index: env[0].index,
            payload: env[0].payload.clone(),
        };
        let result = ShareEnvelope::from_bytes(future.to_bytes().as_slice());
        assert!(
            matches!(result, Err(CryptoError::ShareVersion(_))),
            "a future-version envelope must be a distinct ShareVersion error, got {result:?}"
        );
    }

    #[test]
    fn wrong_length_is_format_error() {
        let result = ShareEnvelope::from_bytes(&[0u8; 10]);
        assert!(matches!(result, Err(CryptoError::ShareFormat(_))));
    }

    #[test]
    fn out_of_range_index_is_format_error() {
        // Hand-build an envelope with index 4 and a valid checksum.
        let bad = ShareEnvelope {
            version: SHARE_ENVELOPE_VERSION,
            set_id: 1,
            index: 4,
            payload: Zeroizing::new([0u8; 32]),
        };
        let result = ShareEnvelope::from_bytes(bad.to_bytes().as_slice());
        assert!(matches!(result, Err(CryptoError::ShareFormat(_))));
    }
}
