use rand_core::{OsRng, RngCore};
use zeroize::Zeroizing;

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

    // ── AC: Splitting a 32-byte secret produces 3 shares ─────────────────────

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

    // ── AC: Any 2 shares reconstruct the original secret ─────────────────────

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

    // ── AC: Single share reveals nothing ─────────────────────────────────────

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
}
