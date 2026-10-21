// pattern: Functional Core

//! AT Protocol identifiers as parsed types.
//!
//! [`Did`] and [`Handle`] can only be built by running the syntax validator, so code holding one
//! never re-checks structure. Both deserialize through the same validator, so a malformed
//! identifier in a request body fails at the boundary rather than deep in a handler.

use std::fmt;
use std::ops::Deref;

use serde::{Deserialize, Serialize};

/// Maximum DID length accepted by the ATProto syntax profile.
const MAX_DID_LEN: usize = 2_048;
/// Maximum total handle length (DNS name limit), per the AT Protocol handle spec.
const MAX_HANDLE_LEN: usize = 253;
/// Maximum length of a single DNS label (RFC 1035).
const MAX_LABEL_LEN: usize = 63;

/// A string that failed [`Did`] or [`Handle`] syntax validation. The message is static and safe
/// to return in a 400 body.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct InvalidIdentifier(pub &'static str);

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

/// Validate that `handle` is structurally a valid AT Protocol handle: a domain name of at
/// least two DNS labels, each 1..=63 chars of ASCII alphanumerics and internal hyphens, with
/// total length at most 253. Returns the first label (the "name") on success.
///
/// This rejects bare single-segment labels (`alice`), which relays and AppViews render as
/// `handle.invalid`.
///
/// # Errors
/// Returns a static message suitable for a 400 response body.
pub fn validate_handle_structure(handle: &str) -> Result<&str, &'static str> {
    if handle.is_empty() {
        return Err("handle must not be empty");
    }
    if handle.len() > MAX_HANDLE_LEN {
        return Err("handle must be at most 253 characters");
    }

    let labels: Vec<&str> = handle.split('.').collect();
    let (Some(first), Some(last)) = (labels.first(), labels.last()) else {
        return Err("handle must not be empty");
    };
    if labels.len() < 2 {
        return Err(
            "handle must be a domain name with at least two parts (e.g. alice.example.com)",
        );
    }
    for label in &labels {
        validate_label(label)?;
    }
    // AT Protocol handle syntax additionally forbids the final label (the effective TLD) from
    // starting with a digit — unlike earlier labels, which may — so a handle can never be
    // confused with an IPv4-literal-shaped name.
    if last.chars().next().is_some_and(|c| c.is_ascii_digit()) {
        return Err("handle's final label must not start with a digit");
    }

    Ok(first)
}

/// Validate a single DNS label: non-empty, at most 63 chars, ASCII alphanumerics and hyphens
/// only, no leading or trailing hyphen.
fn validate_label(label: &str) -> Result<(), &'static str> {
    if label.is_empty() {
        return Err("handle labels must not be empty");
    }
    if label.len() > MAX_LABEL_LEN {
        return Err("handle label exceeds maximum DNS label length of 63 characters");
    }
    if label.starts_with('-') || label.ends_with('-') {
        return Err("handle labels cannot start or end with a hyphen");
    }
    if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
        return Err("handle labels may only contain letters, digits, and hyphens");
    }
    Ok(())
}

/// A DID that passed [`is_valid_did`].
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Did(String);

impl Did {
    /// # Errors
    /// Returns [`InvalidIdentifier`] when `did` is not valid `did:` syntax.
    pub fn parse(did: impl Into<String>) -> Result<Self, InvalidIdentifier> {
        let did = did.into();
        if is_valid_did(&did) {
            Ok(Self(did))
        } else {
            Err(InvalidIdentifier("invalid DID syntax"))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A handle that passed [`validate_handle_structure`].
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Handle {
    value: String,
    /// Byte offset of the first `.`; validation guarantees one exists.
    dot: usize,
}

impl Handle {
    /// # Errors
    /// Returns [`InvalidIdentifier`] carrying the first structural rule `handle` breaks.
    pub fn parse(handle: impl Into<String>) -> Result<Self, InvalidIdentifier> {
        let value = handle.into();
        let dot = validate_handle_structure(&value)
            .map_err(InvalidIdentifier)?
            .len();
        Ok(Self { value, dot })
    }

    pub fn as_str(&self) -> &str {
        &self.value
    }

    /// The first DNS label (`alice` in `alice.example.com`).
    pub fn name(&self) -> &str {
        &self.value[..self.dot]
    }

    /// Everything after the first label (`example.com` in `alice.example.com`).
    pub fn domain(&self) -> &str {
        &self.value[self.dot + 1..]
    }
}

macro_rules! string_newtype {
    ($ty:ident, $field:tt) => {
        impl Deref for $ty {
            type Target = str;
            fn deref(&self) -> &str {
                &self.$field
            }
        }
        impl AsRef<str> for $ty {
            fn as_ref(&self) -> &str {
                &self.$field
            }
        }
        impl fmt::Display for $ty {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.$field)
            }
        }
        impl From<$ty> for String {
            fn from(v: $ty) -> String {
                v.$field
            }
        }
        impl TryFrom<String> for $ty {
            type Error = InvalidIdentifier;
            fn try_from(s: String) -> Result<Self, Self::Error> {
                Self::parse(s)
            }
        }
        impl TryFrom<&str> for $ty {
            type Error = InvalidIdentifier;
            fn try_from(s: &str) -> Result<Self, Self::Error> {
                Self::parse(s)
            }
        }
        impl std::str::FromStr for $ty {
            type Err = InvalidIdentifier;
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Self::parse(s)
            }
        }
        impl PartialEq<str> for $ty {
            fn eq(&self, other: &str) -> bool {
                *self.$field == *other
            }
        }
        impl PartialEq<&str> for $ty {
            fn eq(&self, other: &&str) -> bool {
                *self.$field == **other
            }
        }
        impl PartialEq<String> for $ty {
            fn eq(&self, other: &String) -> bool {
                self.$field == *other
            }
        }
        impl PartialEq<$ty> for String {
            fn eq(&self, other: &$ty) -> bool {
                *self == other.$field
            }
        }
        impl PartialEq<$ty> for &str {
            fn eq(&self, other: &$ty) -> bool {
                **self == *other.$field
            }
        }
        impl PartialEq<$ty> for str {
            fn eq(&self, other: &$ty) -> bool {
                *self == *other.$field
            }
        }
    };
}

string_newtype!(Did, 0);
string_newtype!(Handle, value);

/// SQLite stores both as TEXT. Decoding re-runs the validator, so a malformed stored value
/// surfaces as a decode error rather than an unchecked identifier.
#[cfg(feature = "sqlx")]
macro_rules! sqlite_text {
    ($ty:ident) => {
        impl sqlx::Type<sqlx::Sqlite> for $ty {
            fn type_info() -> sqlx::sqlite::SqliteTypeInfo {
                <String as sqlx::Type<sqlx::Sqlite>>::type_info()
            }
            fn compatible(ty: &sqlx::sqlite::SqliteTypeInfo) -> bool {
                <String as sqlx::Type<sqlx::Sqlite>>::compatible(ty)
            }
        }
        impl<'q> sqlx::Encode<'q, sqlx::Sqlite> for $ty {
            fn encode_by_ref(
                &self,
                buf: &mut Vec<sqlx::sqlite::SqliteArgumentValue<'q>>,
            ) -> Result<sqlx::encode::IsNull, sqlx::error::BoxDynError> {
                <String as sqlx::Encode<'q, sqlx::Sqlite>>::encode(self.as_str().to_owned(), buf)
            }
        }
        impl<'r> sqlx::Decode<'r, sqlx::Sqlite> for $ty {
            fn decode(
                value: sqlx::sqlite::SqliteValueRef<'r>,
            ) -> Result<Self, sqlx::error::BoxDynError> {
                Ok(Self::parse(
                    <String as sqlx::Decode<'r, sqlx::Sqlite>>::decode(value)?,
                )?)
            }
        }
    };
}

#[cfg(feature = "sqlx")]
sqlite_text!(Did);
#[cfg(feature = "sqlx")]
sqlite_text!(Handle);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn did_parse_round_trips_through_serde() {
        let did = Did::parse("did:plc:abc123").unwrap();
        let json = serde_json::to_string(&did).unwrap();
        assert_eq!(json, r#""did:plc:abc123""#);
        assert_eq!(serde_json::from_str::<Did>(&json).unwrap(), did);
    }

    #[test]
    fn did_rejects_bad_syntax_at_parse_and_deserialize() {
        assert!(Did::parse("alice.example.com").is_err());
        assert!(serde_json::from_str::<Did>(r#""did:PLC:x""#).is_err());
    }

    #[test]
    fn handle_splits_name_and_domain() {
        let h = Handle::parse("alice.test.example.com").unwrap();
        assert_eq!(h.name(), "alice");
        assert_eq!(h.domain(), "test.example.com");
        assert_eq!(h, "alice.test.example.com");
    }

    #[test]
    fn handle_rejects_bare_label_with_the_validator_message() {
        assert_eq!(
            Handle::parse("alice").unwrap_err().0,
            "handle must be a domain name with at least two parts (e.g. alice.example.com)",
        );
        assert!(serde_json::from_str::<Handle>(r#""alice""#).is_err());
    }

    // ── validate_handle_structure: accepts valid handles ───────────────────────

    #[test]
    fn structure_accepts_two_label_handle() {
        assert_eq!(validate_handle_structure("alice.example.com"), Ok("alice"));
        assert_eq!(validate_handle_structure("malpercio.dev"), Ok("malpercio"));
        assert_eq!(validate_handle_structure("a.b"), Ok("a"));
    }

    #[test]
    fn structure_accepts_internal_hyphen_in_name() {
        assert_eq!(
            validate_handle_structure("al-ice.example.com"),
            Ok("al-ice")
        );
    }

    #[test]
    fn structure_accepts_label_of_exactly_63_chars() {
        let name = "a".repeat(MAX_LABEL_LEN);
        let handle = format!("{name}.example.com");
        assert_eq!(validate_handle_structure(&handle), Ok(name.as_str()));
    }

    // ── validate_handle_structure: rejects bare labels (the bug) ────────────────

    #[test]
    fn structure_rejects_bare_label() {
        assert!(validate_handle_structure("alice").is_err());
    }

    #[test]
    fn structure_rejects_bare_253_char_label() {
        // The previous permissive validator ACCEPTED this (a 253-char single label with no
        // dot). That acceptance was the bug: it let `at://<label>` reach the genesis op.
        assert!(validate_handle_structure(&"a".repeat(253)).is_err());
    }

    // ── validate_handle_structure: rejects other malformed handles ──────────────

    #[test]
    fn structure_rejects_empty() {
        assert!(validate_handle_structure("").is_err());
    }

    #[test]
    fn structure_rejects_empty_labels() {
        assert!(validate_handle_structure(".example.com").is_err());
        assert!(validate_handle_structure("alice..com").is_err());
        assert!(validate_handle_structure("alice.").is_err());
    }

    #[test]
    fn structure_rejects_leading_or_trailing_hyphen() {
        assert!(validate_handle_structure("-alice.example.com").is_err());
        assert!(validate_handle_structure("alice-.example.com").is_err());
    }

    #[test]
    fn structure_rejects_invalid_characters() {
        assert!(validate_handle_structure("ali_ce.example.com").is_err());
        assert!(validate_handle_structure("alice example.com").is_err());
        assert!(validate_handle_structure("alice\t.example.com").is_err());
    }

    #[test]
    fn structure_rejects_non_ascii() {
        assert!(validate_handle_structure("älice.example.com").is_err());
    }

    #[test]
    fn structure_rejects_numeric_leading_final_label() {
        assert!(validate_handle_structure("alice.123").is_err());
        assert!(validate_handle_structure("alice.example.1com").is_err());
    }

    #[test]
    fn structure_accepts_numeric_leading_non_final_label() {
        // Digits are only forbidden in the final label; an earlier label may start with one.
        assert_eq!(validate_handle_structure("123.example.com"), Ok("123"));
    }

    #[test]
    fn structure_rejects_label_exceeding_63_chars() {
        let name = "a".repeat(MAX_LABEL_LEN + 1);
        assert!(validate_handle_structure(&format!("{name}.example.com")).is_err());
    }

    #[test]
    fn structure_rejects_total_length_over_253() {
        // Four 63-char labels joined by dots = 63*4 + 3 = 255 chars; every label is itself
        // valid, so this isolates the total-length rule.
        let label = "a".repeat(MAX_LABEL_LEN);
        let handle = [label.as_str(); 4].join(".");
        assert!(handle.len() > MAX_HANDLE_LEN);
        assert!(validate_handle_structure(&handle).is_err());
    }
}
