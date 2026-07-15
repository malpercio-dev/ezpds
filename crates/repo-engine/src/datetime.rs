//! Validation for the AT Protocol datetime string format.

use chrono::{DateTime, Datelike, FixedOffset};
use thiserror::Error;

/// Why an AT Protocol datetime was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum AtprotoDatetimeError {
    /// The string does not match the restricted RFC 3339 grammar used by ATProto.
    #[error("datetime does not match the AT Protocol syntax")]
    InvalidSyntax,
    /// The syntax matches, but the calendar value or normalized instant is invalid.
    #[error("datetime is not a parseable AT Protocol instant")]
    Unparseable,
}

/// Validate an AT Protocol datetime, preserving syntax-versus-parse failure information.
///
/// ATProto requires a four-digit year, uppercase `T` and `Z`, seconds, and an explicit
/// timezone. Fractional seconds may contain any positive number of decimal digits. RFC 3339's
/// unknown-local-offset spelling (`-00:00`) is not accepted.
pub fn validate(value: &str) -> Result<(), AtprotoDatetimeError> {
    if !has_valid_syntax(value) {
        return Err(AtprotoDatetimeError::InvalidSyntax);
    }

    let parsed = DateTime::<FixedOffset>::parse_from_rfc3339(value)
        .map_err(|_| AtprotoDatetimeError::Unparseable)?;

    // ATProto permits the ISO year 0000, but not an offset whose UTC normalization crosses into
    // a negative year.
    if parsed.to_utc().year() < 0 {
        return Err(AtprotoDatetimeError::Unparseable);
    }

    Ok(())
}

/// Return whether `value` is both syntactically and semantically valid ATProto datetime text.
pub fn is_valid(value: &str) -> bool {
    validate(value).is_ok()
}

fn has_valid_syntax(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() < 20
        || bytes.get(4) != Some(&b'-')
        || bytes.get(7) != Some(&b'-')
        || bytes.get(10) != Some(&b'T')
        || bytes.get(13) != Some(&b':')
        || bytes.get(16) != Some(&b':')
        || !digits(bytes, 0..4)
        || !digits(bytes, 5..7)
        || !digits(bytes, 8..10)
        || !digits(bytes, 11..13)
        || !digits(bytes, 14..16)
        || !digits(bytes, 17..19)
    {
        return false;
    }

    let mut cursor = 19;
    if bytes.get(cursor) == Some(&b'.') {
        cursor += 1;
        let fraction_start = cursor;
        while bytes.get(cursor).is_some_and(u8::is_ascii_digit) {
            cursor += 1;
        }
        if cursor == fraction_start {
            return false;
        }
    }

    match bytes.get(cursor) {
        Some(b'Z') => cursor + 1 == bytes.len(),
        Some(sign @ (b'+' | b'-')) => {
            let offset = &bytes[cursor..];
            offset.len() == 6
                && offset[3] == b':'
                && digits(offset, 1..3)
                && digits(offset, 4..6)
                && !(*sign == b'-' && &offset[1..] == b"00:00")
        }
        _ => false,
    }
}

fn digits(bytes: &[u8], range: std::ops::Range<usize>) -> bool {
    bytes
        .get(range)
        .is_some_and(|part| part.iter().all(u8::is_ascii_digit))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cases(raw: &str) -> impl Iterator<Item = &str> {
        raw.lines()
            .filter(|line| !line.is_empty() && !line.starts_with("# "))
    }

    fn assert_fixture(valid: &str, syntax_invalid: &str, parse_invalid: &str) {
        for value in cases(valid) {
            assert_eq!(validate(value), Ok(()), "valid vector: {value:?}");
        }
        for value in cases(syntax_invalid) {
            assert_eq!(
                validate(value),
                Err(AtprotoDatetimeError::InvalidSyntax),
                "syntax-invalid vector: {value:?}",
            );
        }
        for value in cases(parse_invalid) {
            assert_eq!(
                validate(value),
                Err(AtprotoDatetimeError::Unparseable),
                "parse-invalid vector: {value:?}",
            );
        }
    }

    #[test]
    fn datetime_validation_matches_interop_fixtures() {
        assert_fixture(
            include_str!("../tests/fixtures/interop/datetime_syntax_valid.txt"),
            include_str!("../tests/fixtures/interop/datetime_syntax_invalid.txt"),
            include_str!("../tests/fixtures/interop/datetime_parse_invalid.txt"),
        );
    }

    #[test]
    #[should_panic(expected = "valid vector")]
    fn corrupted_datetime_fixture_is_detected() {
        assert_fixture(
            include_str!("../tests/fixtures/interop/datetime_syntax_invalid.txt"),
            include_str!("../tests/fixtures/interop/datetime_syntax_invalid.txt"),
            include_str!("../tests/fixtures/interop/datetime_parse_invalid.txt"),
        );
    }

    #[test]
    fn boolean_entry_point_rejects_both_error_classes() {
        assert!(is_valid("1985-04-12T23:20:50.123Z"));
        assert!(!is_valid("1985-04-12 23:20:50.123Z"));
        assert!(!is_valid("1985-13-12T23:20:50.123Z"));
    }
}
