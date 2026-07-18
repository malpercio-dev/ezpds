// pattern: Functional Core
//
//! Validation of a **lexicon document** against the lexicon meta-schema
//! (`https://atproto.com/specs/lexicon`) — "is this lexicon itself well-formed?", the layer
//! *above* records. It does not validate any record; it validates the schema document that
//! records are later checked against.
//!
//! This is distinct from the PDS's `lexicon` module, which parses the *vendored* first-party
//! lexicons into a typed registry and validates XRPC bodies against them. Here the input is an
//! arbitrary, untrusted lexicon document (e.g. a `com.atproto.lexicon.schema` record a user
//! publishes), so the job is to reject a malformed one before it is trusted downstream.
//!
//! Rules enforced (each backed by an interop `lexicon-{valid,invalid}.json` vector):
//!
//! * The document is an object with `lexicon`, `id`, and `defs`.
//! * `lexicon` is the version number, and must be exactly the integer `1`.
//! * `id` is a string and a syntactically valid NSID.
//! * `defs` is an object; each entry is an object with a string `type`.
//! * A **primary** def type (`record`, `query`, `procedure`, `subscription`, `permission-set`)
//!   may only appear under the `main` key.
//! * A def `type` must be a recognized keyword. Reference/composition keywords (`ref`, `union`,
//!   `unknown`) and any unknown keyword are rejected as *standalone* def types.
//! * A `record` def carries a `record` field that is an object of `type: "object"`.

use crate::records::validate_collection;
use serde_json::Value;

/// A lexicon meta-schema validation failure: a human-readable reason plus the def name (or a
/// document-level marker) it applies to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LexiconSchemaError {
    pub location: String,
    pub reason: String,
}

impl std::fmt::Display for LexiconSchemaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "lexicon {}: {}", self.location, self.reason)
    }
}

impl std::error::Error for LexiconSchemaError {}

/// Primary def types — the four ATProto primaries plus `permission-set`. These describe a
/// whole namespaced construct and may only be defined under the `main` key.
const PRIMARY_TYPES: &[&str] = &[
    "record",
    "query",
    "procedure",
    "subscription",
    "permission-set",
];

/// Concrete field/value types that are valid as a standalone (non-`main`) def. The
/// reference/composition keywords `ref`, `union`, and `unknown` are deliberately absent: they
/// only carry meaning as the type of a field *inside* a construct, not as a bare top-level def,
/// so the interop vectors reject them there.
const FIELD_TYPES: &[&str] = &[
    "null", "boolean", "integer", "string", "bytes", "cid-link", "blob", "array", "object", "token",
];

fn error(location: impl Into<String>, reason: impl Into<String>) -> LexiconSchemaError {
    LexiconSchemaError {
        location: location.into(),
        reason: reason.into(),
    }
}

/// Validate a lexicon document against the meta-schema. Returns the first violation found.
pub fn validate_document(doc: &Value) -> Result<(), LexiconSchemaError> {
    let obj = doc
        .as_object()
        .ok_or_else(|| error("document", "must be an object"))?;

    // `lexicon`: the version, exactly the integer 1.
    match obj.get("lexicon") {
        Some(Value::Number(n)) if n.as_u64() == Some(1) => {}
        Some(_) => return Err(error("document", "`lexicon` must be the integer 1")),
        None => return Err(error("document", "missing `lexicon` version field")),
    }

    // `id`: a string, and a valid NSID.
    match obj.get("id") {
        Some(Value::String(id)) => {
            if validate_collection(id).is_err() {
                return Err(error("document", format!("`id` is not a valid NSID: {id}")));
            }
        }
        Some(_) => return Err(error("document", "`id` must be a string")),
        None => return Err(error("document", "missing `id` field")),
    }

    // `defs`: an object of named definitions.
    let defs = match obj.get("defs") {
        Some(Value::Object(defs)) => defs,
        Some(_) => return Err(error("document", "`defs` must be an object")),
        None => return Err(error("document", "missing `defs` field")),
    };

    for (name, def) in defs {
        validate_def(name, def)?;
    }
    Ok(())
}

fn validate_def(name: &str, def: &Value) -> Result<(), LexiconSchemaError> {
    let obj = def
        .as_object()
        .ok_or_else(|| error(name, "definition must be an object"))?;

    let ty = match obj.get("type") {
        Some(Value::String(t)) => t.as_str(),
        Some(_) => return Err(error(name, "`type` must be a string")),
        None => return Err(error(name, "definition is missing `type`")),
    };

    let is_primary = PRIMARY_TYPES.contains(&ty);
    let is_field = FIELD_TYPES.contains(&ty);

    if !is_primary && !is_field {
        return Err(error(
            name,
            format!("`{ty}` is not a valid definition type"),
        ));
    }

    // Primary types describe a whole construct and are only meaningful as the `main` def.
    if is_primary && name != "main" {
        return Err(error(
            name,
            format!("primary type `{ty}` may only be defined under `main`"),
        ));
    }

    // A `record` def wraps its schema in a `record` object of `type: "object"`.
    if ty == "record" {
        match obj.get("record") {
            Some(Value::Object(rec)) => match rec.get("type") {
                Some(Value::String(t)) if t == "object" => {}
                _ => return Err(error(name, "record `record` must have `type: \"object\"`")),
            },
            Some(_) => return Err(error(name, "record `record` must be an object")),
            None => return Err(error(name, "record definition is missing `record`")),
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One entry of the interop `lexicon-{valid,invalid}.json` vectors: a `name` and the
    /// `lexicon` document under test.
    #[derive(serde::Deserialize)]
    struct LexiconCase {
        name: String,
        lexicon: Value,
    }

    fn load(raw: &str) -> Vec<LexiconCase> {
        let cases: Vec<LexiconCase> = serde_json::from_str(raw).expect("parse lexicon vectors");
        assert!(!cases.is_empty(), "lexicon vectors must not be empty");
        cases
    }

    #[test]
    fn accepts_valid_lexicon_vectors() {
        let cases = load(include_str!("../tests/fixtures/interop/lexicon-valid.json"));
        for c in &cases {
            assert!(
                validate_document(&c.lexicon).is_ok(),
                "expected valid ({}): {:?}",
                c.name,
                validate_document(&c.lexicon),
            );
        }
    }

    #[test]
    fn rejects_invalid_lexicon_vectors() {
        let cases = load(include_str!(
            "../tests/fixtures/interop/lexicon-invalid.json"
        ));
        for c in &cases {
            assert!(
                validate_document(&c.lexicon).is_err(),
                "expected invalid ({}): document was accepted",
                c.name,
            );
        }
    }

    #[test]
    #[should_panic(expected = "corrupted valid vector must still validate")]
    fn corrupted_lexicon_fixture_is_detected() {
        // Mutate a known-good lexicon into a known-bad one (`lexicon` version as a string, the
        // very first invalid vector) and assert it still validates — it must not, tripping the
        // gate. Proves the acceptance test is not vacuously passing.
        let corrupt = serde_json::json!({
            "lexicon": "one",
            "id": "example.lexicon.other",
            "defs": { "demo": { "type": "integer" } }
        });
        assert!(
            validate_document(&corrupt).is_ok(),
            "corrupted valid vector must still validate",
        );
    }
}
