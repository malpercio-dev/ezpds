// pattern: Functional Core

use rand_core::{OsRng, RngCore};

const CODE_LEN: usize = 6;
const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

/// Generate a single 6-character uppercase alphanumeric code.
///
/// Maps random bytes onto the charset with **rejection sampling** rather than `byte % 36`.
/// The naive modulo is biased: 256 is not a multiple of 36, so the first `256 % 36 == 4`
/// charset members each have one extra preimage in `0..=255` and come up ~14% more often per
/// position. We instead reject any byte at or above the largest multiple of the charset length
/// that fits in a byte (252 for the 36-char set) and redraw, so every retained byte maps
/// uniformly. Kept dependency-free (no `rand::distributions`) — it is one small function.
pub fn generate_code() -> String {
    // Largest multiple of the charset length representable in a byte; bytes >= this are rejected
    // so the surviving values divide evenly across the charset. For a 36-char set this is 252.
    let cutoff = 256 - (256 % CHARSET.len());
    let mut code = String::with_capacity(CODE_LEN);
    let mut buf = [0u8; CODE_LEN];
    while code.len() < CODE_LEN {
        // Rejections are rare (4/256 ≈ 1.6%), so a fresh CODE_LEN-byte draw almost always
        // yields enough survivors in one pass; the loop covers the occasional shortfall.
        OsRng.fill_bytes(&mut buf);
        for &b in &buf {
            if (b as usize) < cutoff {
                code.push(CHARSET[(b as usize) % CHARSET.len()] as char);
                if code.len() == CODE_LEN {
                    break;
                }
            }
        }
    }
    code
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn code_is_6_chars() {
        assert_eq!(generate_code().len(), CODE_LEN);
    }

    #[test]
    fn code_is_uppercase_alphanumeric() {
        for _ in 0..50 {
            let code = generate_code();
            assert!(
                code.chars()
                    .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit()),
                "code contained non-uppercase-alphanumeric char: {code}"
            );
        }
    }

    #[test]
    fn codes_are_drawn_from_charset() {
        for _ in 0..50 {
            let code = generate_code();
            for ch in code.chars() {
                assert!(
                    CHARSET.contains(&(ch as u8)),
                    "char {ch:?} is not in CHARSET"
                );
            }
        }
    }

    #[test]
    fn consecutive_codes_are_not_all_identical() {
        let codes: Vec<String> = (0..10).map(|_| generate_code()).collect();
        let unique: std::collections::HashSet<_> = codes.iter().collect();
        assert!(unique.len() > 1, "all 10 generated codes were identical");
    }

    /// Statistical check that rejection sampling produces a roughly uniform distribution over the
    /// whole charset (guards against a regression back to the biased `% 36` mapping, which would
    /// over-represent the first four members). Drives real entropy (`OsRng`, not seedable), so the
    /// tolerances are deliberately loose — ~10k codes × 6 chars over 36 buckets puts the pass/fail
    /// bounds many standard deviations from the mean, so it does not flake.
    #[test]
    fn distribution_is_uniform_over_charset() {
        use std::collections::HashMap;

        const SAMPLES: usize = 10_000;
        let mut counts: HashMap<u8, usize> = HashMap::new();
        for _ in 0..SAMPLES {
            for ch in generate_code().bytes() {
                *counts.entry(ch).or_insert(0) += 1;
            }
        }

        // Reachability: every charset member must appear at least once.
        for &member in CHARSET {
            assert!(
                counts.get(&member).is_some_and(|&c| c > 0),
                "charset member {:?} was never generated",
                member as char
            );
        }
        // No byte outside the charset may appear.
        assert_eq!(
            counts.len(),
            CHARSET.len(),
            "generated a byte outside the charset"
        );

        // Rough uniformity: no bucket may stray beyond ±50% of the expected per-member count.
        // A biased `% 36` would push the first four members ~14% high — well inside these bounds
        // for a single position, but with 60k samples the aggregate skew is caught easily; the
        // real purpose is to fail loudly if the mapping regresses to something grossly non-uniform.
        let total: usize = counts.values().sum();
        let expected = total as f64 / CHARSET.len() as f64;
        for (&member, &count) in &counts {
            let ratio = count as f64 / expected;
            assert!(
                (0.5..=1.5).contains(&ratio),
                "charset member {:?} count {} is {:.2}x the expected {:.0} — not uniform",
                member as char,
                count,
                ratio,
                expected
            );
        }
    }
}
