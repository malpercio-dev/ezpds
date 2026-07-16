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

use super::formats::validate_format;
use super::schema::{LexObject, LexSchema};
use super::Registry;

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
        LexSchema::String { format, max_length } => {
            let Value::String(s) = value else {
                return invalid(format!("{path} must be a string"));
            };
            if let Some(max) = max_length {
                if s.len() as u64 > *max {
                    return invalid(format!("{path} must not be longer than {max} characters"));
                }
            }
            if let Some(format) = format {
                if let Err(message) = validate_format(*format, s) {
                    return invalid(format!("{path} {message}"));
                }
            }
            Ok(())
        }
        LexSchema::Boolean => {
            if value.is_boolean() {
                Ok(())
            } else {
                invalid(format!("{path} must be a boolean"))
            }
        }
        LexSchema::Integer { .. } => {
            // `Number.isInteger` in the reference: a float with a zero fraction is an integer.
            let is_integer = value.is_i64()
                || value.is_u64()
                || value.as_f64().is_some_and(|f| f.fract() == 0.0);
            if is_integer {
                Ok(())
            } else {
                invalid(format!("{path} must be an integer"))
            }
        }
        LexSchema::Unknown => {
            if value.is_object() {
                Ok(())
            } else {
                invalid(format!("{path} must be an object"))
            }
        }
        LexSchema::Array { items } => {
            let Value::Array(elements) = value else {
                return invalid(format!("{path} must be an array"));
            };
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

fn invalid(message: String) -> Result<(), ValidationError> {
    Err(ValidationError::Invalid(message))
}
