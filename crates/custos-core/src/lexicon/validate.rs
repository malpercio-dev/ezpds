// pattern: Functional Core
//
// The lexicon schema walker: assert a JSON request body conforms to a procedure's declared
// `input.schema`, mirroring `@atproto/lexicon`'s validators (`assertValidXrpcInput` →
// `validateOneOf` → `object`/`string`/… ) with byte-identical error messages, so a client sees
// the same 400 from Custos as from the reference PDS. Semantics mirrored deliberately:
//
// * Properties are checked in lexicon document order; the first violation wins.
// * A missing required property reports `… must have the property "x"`; an explicit `null` is
//   *not* missing — it falls through to the type check (`… must be a string`) unless the
//   property is listed in `nullable`.
// * Unknown/extra body fields are silently ignored (lexicon objects are open).
// * Open unions accept any object with an unrecognized `$type`; closed unions reject it,
//   printing the fully-qualified `lex:` ref list exactly as the reference does (it rewrites
//   union refs to `lex:` URIs when a document is added).
// * String `maxLength` counts UTF-8 bytes even though the message says "characters" — a
//   reference quirk (`utf8Len`) preserved for parity.

use serde_json::Value;
use unicode_segmentation::UnicodeSegmentation;

use super::formats::{is_valid_record_key, is_valid_tid, validate_format};
use super::schema::{LexObject, LexSchema};
use super::Registry;

/// The `validationStatus` a repo write reports for a record (`applyWrites`/`createRecord`/
/// `putRecord`), mirroring the reference PDS's `'valid' | 'unknown'`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordValidation {
    /// The record validated against a vendored lexicon.
    Valid,
    /// The collection's lexicon is not vendored, so the record is accepted unvalidated.
    Unknown,
}

impl RecordValidation {
    pub fn as_str(self) -> &'static str {
        match self {
            RecordValidation::Valid => "valid",
            RecordValidation::Unknown => "unknown",
        }
    }
}

/// A failed input validation.
pub enum ValidationError {
    /// The body does not conform to the schema — the reference's `InvalidRequest` message,
    /// surfaced to the client as a 400.
    Invalid(String),
    /// The vendored lexicon set itself is broken (dangling ref). Unreachable in practice —
    /// the registry resolves every ref at build time — but kept distinct so it can surface as
    /// a 500 rather than blaming the client.
    Lexicon(String),
}

/// Assert `value` conforms to `schema`, rooted at `path` (`"Input"` for request bodies).
pub(super) fn validate(
    registry: &Registry,
    path: &str,
    schema: &LexSchema,
    value: &Value,
) -> Result<(), ValidationError> {
    match schema {
        LexSchema::Object(object) => validate_object(registry, path, object, value),
        LexSchema::String {
            format,
            min_length,
            max_length,
            max_graphemes,
            enum_values,
            ..
        } => {
            let Value::String(s) = value else {
                return invalid(format!("{path} must be a string"));
            };
            // Order mirrors `@atproto/lexicon`'s string validator: enum, then byte-length bounds,
            // then the grapheme bound, then the format check.
            if !enum_values.is_empty() && !enum_values.iter().any(|e| e == s) {
                return invalid(format!("{path} must be one of ({})", enum_values.join("|")));
            }
            if let Some(max) = max_length {
                if s.len() as u64 > *max {
                    return invalid(format!("{path} must not be longer than {max} characters"));
                }
            }
            if let Some(min) = min_length {
                if (s.len() as u64) < *min {
                    return invalid(format!("{path} must not be shorter than {min} characters"));
                }
            }
            if let Some(max) = max_graphemes {
                if s.graphemes(true).count() as u64 > *max {
                    return invalid(format!("{path} must not be longer than {max} graphemes"));
                }
            }
            if let Some(format) = format {
                if let Err(message) = validate_format(*format, s) {
                    return invalid(format!("{path} {message}"));
                }
            }
            Ok(())
        }
        LexSchema::Boolean { const_value, .. } => {
            let Value::Bool(b) = value else {
                return invalid(format!("{path} must be a boolean"));
            };
            if let Some(expected) = const_value {
                if b != expected {
                    return invalid(format!("{path} must be {expected}"));
                }
            }
            Ok(())
        }
        LexSchema::Integer {
            minimum,
            maximum,
            enum_values,
            ..
        } => {
            // `Number.isInteger` in the reference: a float with a zero fraction is an integer.
            let is_integer = value.is_i64()
                || value.is_u64()
                || value.as_f64().is_some_and(|f| f.fract() == 0.0);
            if !is_integer {
                return invalid(format!("{path} must be an integer"));
            }
            let n = value.as_i64().or_else(|| value.as_f64().map(|f| f as i64));
            if let Some(n) = n {
                if !enum_values.is_empty() && !enum_values.contains(&n) {
                    return invalid(format!(
                        "{path} must be one of ({})",
                        enum_values
                            .iter()
                            .map(i64::to_string)
                            .collect::<Vec<_>>()
                            .join("|")
                    ));
                }
                if let Some(max) = maximum {
                    if n > *max {
                        return invalid(format!("{path} can not be greater than {max}"));
                    }
                }
                if let Some(min) = minimum {
                    if n < *min {
                        return invalid(format!("{path} can not be less than {min}"));
                    }
                }
            }
            Ok(())
        }
        LexSchema::Unknown => {
            if value.is_object() {
                Ok(())
            } else {
                invalid(format!("{path} must be an object"))
            }
        }
        LexSchema::Blob => validate_blob(path, value),
        LexSchema::Bytes => validate_bytes(path, value),
        // No `ref`/`union` in the vendored record closure resolves to a `token`, so a value is
        // never validated against one; if that ever changes, tighten this to the token id string.
        LexSchema::Token => Ok(()),
        LexSchema::Array {
            items,
            min_length,
            max_length,
        } => {
            let Value::Array(elements) = value else {
                return invalid(format!("{path} must be an array"));
            };
            if let Some(max) = max_length {
                if elements.len() as u64 > *max {
                    return invalid(format!("{path} must not have more than {max} elements"));
                }
            }
            if let Some(min) = min_length {
                if (elements.len() as u64) < *min {
                    return invalid(format!("{path} must not have fewer than {min} elements"));
                }
            }
            for (i, element) in elements.iter().enumerate() {
                validate(registry, &format!("{path}/{i}"), items, element)?;
            }
            Ok(())
        }
        LexSchema::Ref { target } => {
            let resolved = registry.resolve(target).ok_or_else(|| {
                ValidationError::Lexicon(format!("lexicon ref {target:?} is not vendored"))
            })?;
            validate(registry, path, resolved, value)
        }
        LexSchema::Union { refs, closed } => validate_union(registry, path, refs, *closed, value),
    }
}

/// Assert a coerced query-params object conforms to `params` (a `type: "params"` def parsed into
/// the same [`LexObject`] shape an input body uses), rooted at `path` (`"Params"`). `value` is
/// the already-coerced object built by `lexicon::params` — absent/empty-string query values are
/// expected to already be omitted, matching the reference's `decodeQueryParams`. This is a thin
/// wrapper: params share the same required/default/type-check semantics as an input body's
/// object properties (`@atproto/lexicon`'s `params()` validator is structurally the same
/// algorithm as its `object()` validator).
pub(super) fn validate_params(
    registry: &Registry,
    path: &str,
    params: &LexObject,
    value: &Value,
) -> Result<(), ValidationError> {
    validate_object(registry, path, params, value)
}

fn validate_object(
    registry: &Registry,
    path: &str,
    object: &LexObject,
    value: &Value,
) -> Result<(), ValidationError> {
    let Value::Object(map) = value else {
        return invalid(format!("{path} must be an object"));
    };
    for (key, property) in &object.properties {
        match map.get(key) {
            None => {
                // A declared default fills the absence before the required check runs (the
                // reference applies primitive defaults inside validation), so a required
                // property with a default is satisfied by an absent value.
                if !property.has_default() && object.required.iter().any(|r| r == key) {
                    return invalid(format!("{path} must have the property \"{key}\""));
                }
            }
            Some(Value::Null) if object.nullable.iter().any(|n| n == key) => {}
            Some(property_value) => {
                validate(registry, &format!("{path}/{key}"), property, property_value)?;
            }
        }
    }
    Ok(())
}

fn validate_union(
    registry: &Registry,
    path: &str,
    refs: &[String],
    closed: bool,
    value: &Value,
) -> Result<(), ValidationError> {
    // The reference's `isDiscriminatedObject`: one message covers both "not an object" and
    // "object without a string $type".
    let type_value = value.as_object().and_then(|map| map.get("$type"));
    let Some(Value::String(type_name)) = type_value else {
        return invalid(format!(
            "{path} must be an object which includes the \"$type\" property"
        ));
    };

    let type_uri = to_lex_uri(type_name);
    let Some(matched) = refs.iter().find(|r| lex_uris_equal(r, &type_uri)) else {
        if closed {
            return invalid(format!("{path} $type must be one of {}", refs.join(", ")));
        }
        // Open union: an unrecognized $type passes — the reference validates only members it
        // knows about.
        return Ok(());
    };

    let resolved = registry.resolve(matched).ok_or_else(|| {
        ValidationError::Lexicon(format!("lexicon union ref {matched:?} is not vendored"))
    })?;
    validate(registry, path, resolved, value)
}

/// Normalize a body-supplied `$type` to a `lex:` URI (`@atproto/lexicon`'s `toLexUri`; body
/// values have no base document, so bare `#frag` values stay as they are and simply won't
/// match any fully-qualified ref).
fn to_lex_uri(type_name: &str) -> String {
    if type_name.starts_with("lex:") {
        type_name.to_owned()
    } else {
        format!("lex:{type_name}")
    }
}

/// Compare two `lex:` URIs treating an absent fragment and `#main` as the same definition
/// (the reference's `refsContainType`).
fn lex_uris_equal(a: &str, b: &str) -> bool {
    canonical_lex_uri(a) == canonical_lex_uri(b)
}

fn canonical_lex_uri(uri: &str) -> &str {
    uri.strip_suffix("#main").unwrap_or(uri)
}

/// `assertValidRecord`-parity record validation for a repo write. See
/// [`Registry::validate_record`](super::Registry::validate_record) for the decision table.
pub(super) fn validate_record(
    registry: &Registry,
    collection: &str,
    rkey: &str,
    record: &Value,
    validate: Option<bool>,
) -> Result<Option<RecordValidation>, ValidationError> {
    // `prepareWrite` computes the record's `$type` before validation: an absent `$type` is
    // treated as the collection, and a present one that differs is rejected regardless of the
    // `validate` flag.
    if let Some(ty) = record.get("$type") {
        let matches = matches!(ty, Value::String(s) if s == collection);
        if !matches {
            let got = match ty {
                Value::String(s) => s.clone(),
                other => other.to_string(),
            };
            return Err(ValidationError::Invalid(format!(
                "Invalid $type: expected {collection}, got {got}"
            )));
        }
    }

    if validate == Some(false) {
        return Ok(None);
    }

    let Some(record_def) = registry.record(collection) else {
        if validate == Some(true) {
            return Err(ValidationError::Invalid(format!(
                "Unknown lexicon type: {collection}"
            )));
        }
        // Default validation leaves unknown collections writable, flagged `unknown`.
        return Ok(Some(RecordValidation::Unknown));
    };

    validate_record_key(&record_def.key, rkey).map_err(|reason| {
        ValidationError::Invalid(format!("Invalid record key for {collection}: {reason}"))
    })?;

    match self::validate(registry, "Record", &record_def.record, record) {
        Ok(()) => Ok(Some(RecordValidation::Valid)),
        Err(ValidationError::Invalid(message)) => Err(ValidationError::Invalid(format!(
            "Invalid {collection} record: {message}"
        ))),
        Err(other) => Err(other),
    }
}

/// Validate a record key against a `record` def's `key` discipline (`tid`, `literal:<value>`,
/// `nsid`, `any`), mirroring `@atproto/lexicon`'s per-key-type key schema.
fn validate_record_key(key: &str, rkey: &str) -> Result<(), String> {
    if let Some(expected) = key.strip_prefix("literal:") {
        return if rkey == expected {
            Ok(())
        } else {
            Err(format!(
                "record key must be the literal \"{expected}\", got \"{rkey}\""
            ))
        };
    }
    match key {
        "tid" => {
            if is_valid_tid(rkey) {
                Ok(())
            } else {
                Err(format!("record key is not a valid TID: \"{rkey}\""))
            }
        }
        "nsid" => {
            if repo_engine::validate_collection(rkey).is_ok() {
                Ok(())
            } else {
                Err(format!("record key is not a valid NSID: \"{rkey}\""))
            }
        }
        "any" => {
            if is_valid_record_key(rkey) {
                Ok(())
            } else {
                Err(format!("record key syntax is invalid: \"{rkey}\""))
            }
        }
        other => Err(format!("unsupported record key type: {other}")),
    }
}

/// Validate a lex-JSON blob ref: the typed form `{ "$type": "blob", "ref": { "$link": "<cid>" },
/// "mimeType": "…", "size": N }` or the legacy `{ "cid": "<cid>", "mimeType": "…" }`. Blob
/// `accept`/`maxSize` are enforced against the uploaded blob's metadata elsewhere, not here.
fn validate_blob(path: &str, value: &Value) -> Result<(), ValidationError> {
    let Value::Object(map) = value else {
        return invalid(format!("{path} must be a blob ref"));
    };
    let is_typed = map.get("$type").and_then(Value::as_str) == Some("blob");
    let ok = if is_typed {
        let link_is_cid = map
            .get("ref")
            .and_then(|r| r.get("$link"))
            .and_then(Value::as_str)
            .is_some_and(|cid| repo_engine::Cid::try_from(cid).is_ok());
        link_is_cid && map.get("mimeType").and_then(Value::as_str).is_some()
    } else {
        map.get("cid").and_then(Value::as_str).is_some()
            && map.get("mimeType").and_then(Value::as_str).is_some()
    };
    if ok {
        Ok(())
    } else {
        invalid(format!("{path} must be a blob ref"))
    }
}

/// Validate lex-JSON bytes: `{ "$bytes": "<base64>" }`.
fn validate_bytes(path: &str, value: &Value) -> Result<(), ValidationError> {
    if value.get("$bytes").and_then(Value::as_str).is_some() {
        Ok(())
    } else {
        invalid(format!("{path} must be a byte array"))
    }
}

fn invalid(message: String) -> Result<(), ValidationError> {
    Err(ValidationError::Invalid(message))
}
