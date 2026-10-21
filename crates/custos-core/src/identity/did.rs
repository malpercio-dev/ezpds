// pattern: Functional Core

//! General DID syntax validation for the ATProto identity layer. The validator lives in
//! `common` (it backs [`common::Did`]); the interop-fixture test stays here.

pub use common::is_valid_did;

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
