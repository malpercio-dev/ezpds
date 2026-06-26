use rand_core::{OsRng, RngCore};

const CODE_LEN: usize = 6;
const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

/// Generate a single 6-character uppercase alphanumeric code.
pub fn generate_code() -> String {
    let mut buf = [0u8; CODE_LEN];
    OsRng.fill_bytes(&mut buf);
    buf.iter()
        .map(|&b| CHARSET[(b as usize) % CHARSET.len()] as char)
        .collect()
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
        // Every character in a generated code must appear in CHARSET.
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
        // With 36^6 ≈ 2.2 billion possible codes, the probability that 10 consecutive
        // calls all return the same code is negligibly small. This test catches a broken
        // RNG or constant-return implementation.
        let codes: Vec<String> = (0..10).map(|_| generate_code()).collect();
        let unique: std::collections::HashSet<_> = codes.iter().collect();
        assert!(unique.len() > 1, "all 10 generated codes were identical");
    }
}
