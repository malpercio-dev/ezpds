// pattern: Functional Core
//
// String `format` checks for lexicon validation, dispatching to the workspace's existing
// reference-parity syntax validators (each already tested against the atproto interop fixture
// vectors) and filling the one gap (`record-key`, which previously existed only fused into
// `repo_engine::validate_record_path`).
//
// Error messages are byte-identical to `@atproto/lexicon`'s `formats.ts` so a client sees the
// same rejection from Custos as from the reference PDS; the validator prefixes each with the
// failing path (e.g. `Input/handle must be a valid handle`).

use super::schema::StringFormat;

/// Check `value` against `format`. On failure returns the reference's message suffix — the
/// caller prepends the JSON path.
pub(super) fn validate_format(format: StringFormat, value: &str) -> Result<(), &'static str> {
    let ok = match format {
        StringFormat::AtIdentifier => {
            if value.starts_with("did:") {
                crate::identity::did::is_valid_did(value)
            } else {
                is_valid_handle(value)
            }
        }
        StringFormat::AtUri => repo_engine::AtUri::parse(value).is_ok(),
        StringFormat::Cid => repo_engine::Cid::try_from(value).is_ok(),
        StringFormat::Datetime => repo_engine::is_valid_datetime(value),
        StringFormat::Did => crate::identity::did::is_valid_did(value),
        StringFormat::Handle => is_valid_handle(value),
        StringFormat::Language => is_valid_language(value),
        StringFormat::Nsid => repo_engine::validate_collection(value).is_ok(),
        StringFormat::RecordKey => is_valid_record_key(value),
        StringFormat::Tid => is_valid_tid(value),
        StringFormat::Uri => is_valid_uri(value),
    };
    if ok {
        return Ok(());
    }
    Err(match format {
        StringFormat::AtIdentifier => "must be a valid did or a handle",
        StringFormat::AtUri => "must be a valid at-uri",
        StringFormat::Cid => "must be a cid string",
        // Reference message quoted verbatim, grammatical quirk included.
        StringFormat::Datetime => "must be an valid atproto datetime (both RFC-3339 and ISO-8601)",
        StringFormat::Did => "must be a valid did",
        StringFormat::Handle => "must be a valid handle",
        StringFormat::Language => "must be a well-formed BCP 47 language tag",
        StringFormat::Nsid => "must be a valid nsid",
        StringFormat::RecordKey => "must be a valid Record Key",
        StringFormat::Tid => "must be a valid TID",
        StringFormat::Uri => "must be a uri",
    })
}

/// Syntactic BCP 47 check for the lexicon `language` format: one or more `-`-separated subtags of
/// 1–8 alphanumerics, the first alphabetic. Deliberately permissive (structure, not registry
/// membership) — the reference rejects only structurally malformed tags on the write path.
fn is_valid_language(value: &str) -> bool {
    if value.is_empty() {
        return false;
    }
    let mut subtags = value.split('-');
    let Some(first) = subtags.next() else {
        return false;
    };
    let subtag_ok = |t: &str, alpha_only: bool| {
        !t.is_empty()
            && t.len() <= 8
            && t.bytes()
                .all(|b| b.is_ascii_alphanumeric() && (!alpha_only || b.is_ascii_alphabetic()))
    };
    subtag_ok(first, true) && subtags.all(|t| subtag_ok(t, false))
}

/// Structural check for the lexicon `uri` format: a scheme (`[a-z][a-z0-9+.-]*:`) followed by a
/// non-empty, whitespace-free remainder. Mirrors `@atproto/lexicon`'s permissive URI check.
fn is_valid_uri(value: &str) -> bool {
    let Some(colon) = value.find(':') else {
        return false;
    };
    if colon == 0 || value.len() == colon + 1 {
        return false;
    }
    let scheme = &value[..colon];
    let mut scheme_bytes = scheme.bytes();
    let head_ok = scheme_bytes.next().is_some_and(|b| b.is_ascii_alphabetic());
    let tail_ok =
        scheme_bytes.all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'.' | b'-'));
    head_ok && tail_ok && !value.chars().any(char::is_whitespace)
}

/// Structural handle syntax only — the lexicon `handle` format is pure syntax
/// (`@atproto/syntax`'s `ensureValidHandle`), so the server's domain policy and reserved-name
/// rules (`identity::handle::validate_handle`) deliberately do not apply here.
fn is_valid_handle(value: &str) -> bool {
    crate::identity::handle::validate_handle_structure(value).is_ok()
}

/// Record-key syntax per `@atproto/syntax`'s `ensureValidRecordKey`: 1–512 chars of
/// `[A-Za-z0-9._~:-]`, and not the path-traversal literals `.` / `..`.
pub(super) fn is_valid_record_key(value: &str) -> bool {
    if value.is_empty() || value.len() > 512 || value == "." || value == ".." {
        return false;
    }
    value
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'~' | b':' | b'-'))
}

/// TID syntax per `@atproto/syntax`'s `ensureValidTid`: exactly 13 chars from the base32-sortable
/// alphabet, with the high bit clear (first char in `[234567abcdefghij]`).
pub(super) fn is_valid_tid(value: &str) -> bool {
    const ALPHABET: &str = "234567abcdefghijklmnopqrstuvwxyz";
    if value.len() != 13 {
        return false;
    }
    let mut chars = value.chars();
    let first = chars.next().expect("length checked above");
    "234567abcdefghij".contains(first) && value.chars().all(|c| ALPHABET.contains(c))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_key_accepts_valid_keys() {
        for key in [
            "3jui7kd54zh2y",
            "self",
            "example.com",
            "~1.2-3_",
            "pre:fix",
            "_",
        ] {
            assert!(is_valid_record_key(key), "expected valid: {key:?}");
        }
    }

    #[test]
    fn record_key_rejects_invalid_keys() {
        let too_long = "a".repeat(513);
        for key in [
            "",
            ".",
            "..",
            "alpha/beta",
            "@handle",
            "any space",
            too_long.as_str(),
        ] {
            assert!(!is_valid_record_key(key), "expected invalid: {key:?}");
        }
    }

    #[test]
    fn at_identifier_accepts_both_shapes() {
        assert!(validate_format(StringFormat::AtIdentifier, "did:plc:aaaabbbbccccdddd").is_ok());
        assert!(validate_format(StringFormat::AtIdentifier, "alice.example.com").is_ok());
        assert_eq!(
            validate_format(StringFormat::AtIdentifier, "not an identifier"),
            Err("must be a valid did or a handle")
        );
    }

    #[test]
    fn cid_parses_real_cids_only() {
        assert!(validate_format(
            StringFormat::Cid,
            "bafyreidfayvfuwqa7qlnopdjiqrxzs6blmoeu4rujcjtnci5beludirz2a"
        )
        .is_ok());
        assert_eq!(
            validate_format(StringFormat::Cid, "not-a-cid"),
            Err("must be a cid string")
        );
    }
}
