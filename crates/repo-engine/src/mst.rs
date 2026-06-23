// pattern: Functional Core

//! MST utility functions matching the ATProto specification.
//!
//! These are the canonical algorithms for key layering and prefix compression
//! used by the Merkle Search Tree. They are kept here so we can verify them
//! against the official interop test fixtures.

use sha2::Digest;

/// Count the number of leading zero 2-bit groups in the SHA-256 hash of `key`.
///
/// This determines the MST layer at which a key is placed:
/// - 0 leading zero pairs → layer 0
/// - 1 leading zero pair  → layer 1
/// - etc.
///
/// Reference: https://atproto.com/specs/repository#mst-structure
/// Reference: https://github.com/nicholasgasior/atproto-interop-tests/blob/main/mst/key_heights.json
pub fn leading_zero_bitpairs(key: &[u8]) -> usize {
    let digest = sha2::Sha256::digest(key);
    let mut zeroes = 0;

    for byte in digest.iter() {
        // Each condition checks one 2-bit group, from most significant to least.
        zeroes += (*byte < 0b0100_0000) as usize;
        zeroes += (*byte < 0b0001_0000) as usize;
        zeroes += (*byte < 0b0000_0100) as usize;
        zeroes += (*byte < 0b0000_0001) as usize;

        if *byte != 0 {
            break;
        }
    }

    zeroes
}

/// Count the length of the common prefix between two byte slices.
///
/// Used for MST prefix compression: when two adjacent keys share a prefix,
/// only the prefix length and the remaining suffix are stored.
///
/// Reference: https://atproto.com/specs/repository#mst-structure
pub fn common_prefix_len(left: &[u8], right: &[u8]) -> usize {
    left.iter()
        .zip(right.iter())
        .take_while(|(a, b)| a == b)
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;

    // Interop fixture: key_heights.json
    // CC-0 licensed, from bluesky-social/atproto-interop-tests
    #[test]
    fn key_heights_match_interop_fixture() {
        let fixtures: &[(&str, usize)] = &[
            ("", 0),
            ("asdf", 0),
            ("blue", 1),
            ("2653ae71", 0),
            ("88bfafc7", 2),
            ("2a92d355", 4),
            ("884976f5", 6),
            ("app.bsky.feed.post/454397e440ec", 4),
            ("app.bsky.feed.post/9adeb165882c", 8),
        ];

        for (key, expected_height) in fixtures {
            let computed = leading_zero_bitpairs(key.as_bytes());
            assert_eq!(
                computed, *expected_height,
                "key={key:?}: expected height {expected_height}, got {computed}",
            );
        }
    }

    // Deliberately corrupted fixture: one key's expected height is wrong.
    // The gate must catch this — if it passes, the test itself is broken.
    #[test]
    #[should_panic(expected = "expected height")]
    fn corrupted_key_height_fixture_is_detected() {
        let key = "blue";
        let wrong_height = 99; // deliberately wrong
        let computed = leading_zero_bitpairs(key.as_bytes());
        assert_eq!(
            computed, wrong_height,
            "expected height {wrong_height} for key={key:?}"
        );
    }

    // Interop fixture: common_prefix.json
    // CC-0 licensed, from bluesky-social/atproto-interop-tests
    #[test]
    fn common_prefix_lengths_match_interop_fixture() {
        let fixtures: &[(&str, &str, usize)] = &[
            ("", "", 0),
            ("abc", "abc", 3),
            ("", "abc", 0),
            ("abc", "", 0),
            ("ab", "abc", 2),
            ("abc", "ab", 2),
            ("abcde", "abc", 3),
            ("abc", "abcde", 3),
            ("abcde", "abc1", 3),
            ("abcde", "abb", 2),
            ("abcde", "qbb", 0),
            ("abc", "abc\0", 3),
            ("abc\0", "abc", 3),
        ];

        for (left, right, expected_len) in fixtures {
            let computed = common_prefix_len(left.as_bytes(), right.as_bytes());
            assert_eq!(
                computed, *expected_len,
                "common_prefix_len({left:?}, {right:?}): expected {expected_len}, got {computed}",
            );
        }
    }

    // Deliberately corrupted fixture: wrong expected prefix length.
    #[test]
    #[should_panic(expected = "expected 99")]
    fn corrupted_prefix_length_fixture_is_detected() {
        let left = "abc";
        let right = "abcde";
        let wrong_len = 99; // deliberately wrong
        let computed = common_prefix_len(left.as_bytes(), right.as_bytes());
        assert_eq!(
            computed, wrong_len,
            "expected {wrong_len} for ({left:?}, {right:?})"
        );
    }
}
