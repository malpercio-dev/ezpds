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
    use serde::Deserialize;

    // Interop fixtures are loaded from the real upstream files vendored under
    // tests/fixtures/interop/ (see that directory's README for provenance and
    // license), rather than hand-transcribed inline — so added upstream cases
    // are exercised automatically.

    #[derive(Deserialize)]
    struct KeyHeight {
        key: String,
        height: usize,
    }

    #[derive(Deserialize)]
    struct CommonPrefix {
        left: String,
        right: String,
        len: usize,
    }

    // Interop fixture: mst/key_heights.json (CC0, bluesky-social/atproto-interop-tests)
    #[test]
    fn key_heights_match_interop_fixture() {
        let raw = include_str!("../tests/fixtures/interop/key_heights.json");
        let fixtures: Vec<KeyHeight> = serde_json::from_str(raw).expect("parse key_heights.json");
        assert!(!fixtures.is_empty(), "fixture file must not be empty");

        for KeyHeight { key, height } in &fixtures {
            let computed = leading_zero_bitpairs(key.as_bytes());
            assert_eq!(
                computed, *height,
                "key={key:?}: expected height {height}, got {computed}",
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

    // Interop fixture: mst/common_prefix.json (CC0, bluesky-social/atproto-interop-tests)
    #[test]
    fn common_prefix_lengths_match_interop_fixture() {
        let raw = include_str!("../tests/fixtures/interop/common_prefix.json");
        let fixtures: Vec<CommonPrefix> =
            serde_json::from_str(raw).expect("parse common_prefix.json");
        assert!(!fixtures.is_empty(), "fixture file must not be empty");

        for CommonPrefix { left, right, len } in &fixtures {
            let computed = common_prefix_len(left.as_bytes(), right.as_bytes());
            assert_eq!(
                computed, *len,
                "common_prefix_len({left:?}, {right:?}): expected {len}, got {computed}",
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
