// pattern: Functional Core

//! General DID syntax validation for the ATProto identity layer.

/// Maximum DID length accepted by the ATProto syntax profile.
const MAX_DID_LEN: usize = 2_048;

/// Validate the general `did:` syntax used by ATProto.
///
/// Method-specific rules such as the shape of `did:plc` identifiers or the URL encoding in
/// `did:web` remain the responsibility of those method implementations.
pub fn is_valid_did(did: &str) -> bool {
    if did.len() > MAX_DID_LEN {
        return false;
    }

    let Some(rest) = did.strip_prefix("did:") else {
        return false;
    };
    let Some((method, method_specific_id)) = rest.split_once(':') else {
        return false;
    };
    if method.is_empty()
        || !method.bytes().all(|byte| byte.is_ascii_lowercase())
        || method_specific_id.is_empty()
        || method_specific_id.ends_with(':')
    {
        return false;
    }

    let mut bytes = method_specific_id.bytes();
    while let Some(byte) = bytes.next() {
        match byte {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'.' | b'-' | b'_' | b':' => {}
            b'%' => {
                let (Some(high), Some(low)) = (bytes.next(), bytes.next()) else {
                    return false;
                };
                if !high.is_ascii_hexdigit() || !low.is_ascii_hexdigit() {
                    return false;
                }
            }
            _ => return false,
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn load_syntax_cases(raw: &str) -> Vec<&str> {
        raw.lines()
            .map(|line| line.strip_suffix('\r').unwrap_or(line))
            .filter(|line| !line.trim().is_empty() && !line.starts_with("# "))
            .collect()
    }

    fn assert_did_syntax_cases(valid_raw: &str, invalid_raw: &str) {
        let valid = load_syntax_cases(valid_raw);
        let invalid = load_syntax_cases(invalid_raw);
        assert!(!valid.is_empty() && !invalid.is_empty());

        for did in valid {
            assert!(
                is_valid_did(did),
                "expected valid DID from interop fixture: {did:?}",
            );
        }
        for did in invalid {
            assert!(
                !is_valid_did(did),
                "expected invalid DID from interop fixture: {did:?}",
            );
        }
    }

    #[test]
    fn syntax_matches_interop_fixtures() {
        assert_did_syntax_cases(
            include_str!("../../tests/fixtures/interop/did_syntax_valid.txt"),
            include_str!("../../tests/fixtures/interop/did_syntax_invalid.txt"),
        );
    }

    #[test]
    #[should_panic(expected = "expected valid DID from interop fixture")]
    fn corrupted_did_fixture_is_detected() {
        assert_did_syntax_cases(
            include_str!("../../tests/fixtures/interop/did_syntax_invalid.txt"),
            include_str!("../../tests/fixtures/interop/did_syntax_valid.txt"),
        );
    }
}
