//! Parsing and validation for AT Protocol URIs.

use crate::records::{validate_collection, validate_record_path};
use std::fmt;

/// A validated, borrowed decomposition of an `at://` URI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AtUri<'a> {
    pub authority: &'a str,
    pub collection: Option<&'a str>,
    pub rkey: Option<&'a str>,
    /// Reserved for compatibility with URI-shaped callers. AT-URI syntax currently
    /// rejects fragments, so this is `None` for every successfully parsed value.
    pub fragment: Option<&'a str>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AtUriError(&'static str);

impl fmt::Display for AtUriError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid AT-URI: {}", self.0)
    }
}

impl std::error::Error for AtUriError {}

impl<'a> AtUri<'a> {
    /// Parse and validate an AT-URI according to the ATProto syntax grammar.
    pub fn parse(value: &'a str) -> Result<Self, AtUriError> {
        if value.len() > 8_192 {
            return Err(AtUriError("URI exceeds 8192 bytes"));
        }
        let rest = value
            .strip_prefix("at://")
            .ok_or(AtUriError("scheme must be `at://`"))?;
        if rest.contains('#') {
            return Err(AtUriError("fragments are not part of AT-URI syntax"));
        }

        let mut parts = rest.split('/');
        let authority = parts.next().ok_or(AtUriError("missing authority"))?;
        validate_authority(authority)?;
        let collection = parts.next();
        let rkey = parts.next();
        if parts.next().is_some() {
            return Err(AtUriError("too many path segments"));
        }

        match (collection, rkey) {
            (None, None) => {}
            (Some(collection), None) => {
                validate_collection(collection)
                    .map_err(|_| AtUriError("invalid collection NSID"))?;
            }
            (Some(collection), Some(rkey)) => {
                validate_record_path(collection, rkey)
                    .map_err(|_| AtUriError("invalid collection or record key"))?;
            }
            (None, Some(_)) => unreachable!("a record key cannot precede its collection"),
        }

        Ok(Self {
            authority,
            collection,
            rkey,
            fragment: None,
        })
    }
}

fn validate_authority(authority: &str) -> Result<(), AtUriError> {
    if authority.starts_with("did:") {
        return validate_did(authority);
    }
    validate_handle(authority)
}

fn validate_did(did: &str) -> Result<(), AtUriError> {
    if did.len() > 2_048 {
        return Err(AtUriError("invalid DID authority"));
    }
    let mut parts = did.splitn(3, ':');
    if parts.next() != Some("did") {
        return Err(AtUriError("invalid DID authority"));
    }
    let method = parts.next().ok_or(AtUriError("invalid DID authority"))?;
    let identifier = parts.next().ok_or(AtUriError("invalid DID authority"))?;
    if method.is_empty()
        || !method.bytes().all(|byte| byte.is_ascii_lowercase())
        || identifier.is_empty()
        || identifier.ends_with(':')
        || !identifier.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b':' | b'%')
        })
    {
        return Err(AtUriError("invalid DID authority"));
    }
    Ok(())
}

fn validate_handle(handle: &str) -> Result<(), AtUriError> {
    if handle.is_empty() || handle.len() > 253 {
        return Err(AtUriError("invalid handle authority"));
    }
    let labels: Vec<&str> = handle.split('.').collect();
    if labels.len() < 2 {
        return Err(AtUriError("invalid handle authority"));
    }
    for label in &labels {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(AtUriError("invalid handle authority"));
        }
    }
    if !labels.last().is_some_and(|label| {
        label
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_alphabetic())
    }) {
        return Err(AtUriError("invalid handle authority"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::AtUri;

    fn cases(raw: &str) -> impl Iterator<Item = &str> {
        raw.lines()
            .filter(|line| !line.is_empty() && !line.starts_with("# "))
    }

    fn assert_fixture(valid: &str, invalid: &str) {
        for value in cases(valid) {
            assert!(
                AtUri::parse(value).is_ok(),
                "expected valid AT-URI: {value:?}"
            );
        }
        for value in cases(invalid) {
            assert!(
                AtUri::parse(value).is_err(),
                "expected invalid AT-URI: {value:?}"
            );
        }
    }

    #[test]
    fn decomposes_typed_components() {
        let uri = AtUri::parse("at://did:plc:asdf123/com.atproto.feed.post/record").unwrap();
        assert_eq!(uri.authority, "did:plc:asdf123");
        assert_eq!(uri.collection, Some("com.atproto.feed.post"));
        assert_eq!(uri.rkey, Some("record"));
        assert_eq!(uri.fragment, None);

        let handle = AtUri::parse("at://user.bsky.social").unwrap();
        assert_eq!(handle.authority, "user.bsky.social");
        assert_eq!(handle.collection, None);
        assert_eq!(handle.rkey, None);
    }

    #[test]
    fn matches_interop_fixtures() {
        assert_fixture(
            include_str!("../tests/fixtures/interop/aturi_syntax_valid.txt"),
            include_str!("../tests/fixtures/interop/aturi_syntax_invalid.txt"),
        );
    }

    #[test]
    #[should_panic(expected = "expected valid AT-URI")]
    fn corrupted_fixture_is_detected() {
        assert_fixture(
            include_str!("../tests/fixtures/interop/aturi_syntax_invalid.txt"),
            include_str!("../tests/fixtures/interop/aturi_syntax_valid.txt"),
        );
    }
}
