// pattern: Functional Core
//
//! Two layers of lexicon validation over **arbitrary, untrusted** lexicon documents (e.g. a
//! `com.atproto.lexicon.schema` record a user publishes), keyed on `https://atproto.com/specs/lexicon`:
//!
//! * [`validate_document`] — the meta-schema layer: "is this lexicon document itself
//!   well-formed?", the layer *above* records. It validates the schema document, not any record.
//! * [`validate_record`] — the record-data layer: given a (well-formed) lexicon document and one
//!   of its `record` defs, "does this record conform?" — resolving refs/unions within the
//!   document and enforcing the field types, formats, and record-key discipline the def declares.
//!   Backed by the `record-data-{valid,invalid}.json` + `lexicon-record.json` interop vectors.
//!
//! Both are distinct from the PDS's `lexicon` module, which parses the *vendored* first-party
//! lexicons into a typed registry and validates XRPC bodies against them. There the schemas are
//! trusted and fixed; here the input is arbitrary and untrusted, so the job is to reject a
//! malformed document — or a record that violates one — before it is trusted downstream.
//!
//! Meta-schema rules enforced by [`validate_document`] (each backed by an interop
//! `lexicon-{valid,invalid}.json` vector):
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
use crate::{AtUri, Cid};
use base64::Engine;
use serde_json::Value;
use unicode_segmentation::UnicodeSegmentation;

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

/// A record-data validation failure, including the path at which the resolved schema failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LexiconRecordError {
    pub path: String,
    pub reason: String,
}

impl std::fmt::Display for LexiconRecordError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "record at `{}`: {}", self.path, self.reason)
    }
}

impl std::error::Error for LexiconRecordError {}

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

/// Validate `record` against a record definition in an arbitrary resolved lexicon document.
///
/// `def_name` is normally `main`. References and union members are resolved within `doc`; fully
/// qualified references must name the document's own NSID. Callers should first pass untrusted
/// documents through [`validate_document`].
pub fn validate_record(
    doc: &Value,
    def_name: &str,
    rkey: &str,
    record: &Value,
) -> Result<(), LexiconRecordError> {
    let doc_obj = object(doc, "lexicon")?;
    let id = doc_obj
        .get("id")
        .and_then(Value::as_str)
        .ok_or_else(|| record_error("lexicon", "missing string `id`"))?;
    let defs = doc_obj
        .get("defs")
        .and_then(Value::as_object)
        .ok_or_else(|| record_error("lexicon", "missing object `defs`"))?;
    let def = defs
        .get(def_name)
        .ok_or_else(|| record_error("lexicon", format!("unknown definition `{def_name}`")))?;
    let def_obj = object(def, "lexicon definition")?;
    if def_obj.get("type").and_then(Value::as_str) != Some("record") {
        return Err(record_error(
            "lexicon definition",
            "must have type `record`",
        ));
    }
    validate_record_key(
        def_obj.get("key").and_then(Value::as_str).unwrap_or("any"),
        rkey,
    )?;
    let expected_type = if def_name == "main" {
        id.to_owned()
    } else {
        format!("{id}#{def_name}")
    };
    if let Some(actual) = record.get("$type") {
        if actual.as_str() != Some(&expected_type) {
            return Err(record_error("$type", format!("must be `{expected_type}`")));
        }
    }
    let schema = def_obj
        .get("record")
        .ok_or_else(|| record_error("lexicon definition", "missing `record` schema"))?;
    validate_schema(doc_obj, id, schema, "record", record)
}

fn record_error(path: impl Into<String>, reason: impl Into<String>) -> LexiconRecordError {
    LexiconRecordError {
        path: path.into(),
        reason: reason.into(),
    }
}

fn object<'a>(
    value: &'a Value,
    path: &str,
) -> Result<&'a serde_json::Map<String, Value>, LexiconRecordError> {
    value
        .as_object()
        .ok_or_else(|| record_error(path, "must be an object"))
}

fn property_path(path: &str, key: &str) -> String {
    format!("{path}/{key}")
}

fn validate_schema(
    doc: &serde_json::Map<String, Value>,
    id: &str,
    schema: &Value,
    path: &str,
    value: &Value,
) -> Result<(), LexiconRecordError> {
    let node = object(schema, path)?;
    let ty = node
        .get("type")
        .and_then(Value::as_str)
        .ok_or_else(|| record_error(path, "schema is missing string `type`"))?;
    match ty {
        "null" if value.is_null() => Ok(()),
        "boolean" => {
            let Some(actual) = value.as_bool() else {
                return Err(record_error(path, "must be a boolean"));
            };
            if node
                .get("const")
                .and_then(Value::as_bool)
                .is_some_and(|expected| actual != expected)
            {
                return Err(record_error(path, "does not match `const`"));
            }
            Ok(())
        }
        "integer" => validate_integer(node, path, value),
        "string" => validate_string(node, path, value),
        "bytes" => validate_bytes(node, path, value),
        "cid-link" => validate_cid_link(path, value),
        "blob" => validate_blob(node, path, value),
        "array" => validate_array(doc, id, node, path, value),
        "object" => validate_object_schema(doc, id, node, path, value),
        "unknown" => validate_unknown(path, value),
        "ref" => {
            let reference = node
                .get("ref")
                .and_then(Value::as_str)
                .ok_or_else(|| record_error(path, "ref schema is missing `ref`"))?;
            let resolved = resolve_ref(doc, id, reference, path)?;
            validate_schema(doc, id, resolved, path, value)
        }
        "union" => validate_union(doc, id, node, path, value),
        "token" => value
            .as_str()
            .filter(|actual| {
                **actual == canonical_ref(id, node.get("ref").and_then(Value::as_str).unwrap_or(""))
            })
            .map(|_| ())
            .ok_or_else(|| record_error(path, "must be a token identifier")),
        _ => Err(record_error(
            path,
            format!("unsupported schema type `{ty}`"),
        )),
    }
}

fn validate_integer(
    node: &serde_json::Map<String, Value>,
    path: &str,
    value: &Value,
) -> Result<(), LexiconRecordError> {
    let integer = value
        .as_i64()
        .or_else(|| {
            value
                .as_f64()
                .filter(|number| number.fract() == 0.0)
                .map(|number| number as i64)
        })
        .ok_or_else(|| record_error(path, "must be an integer"))?;
    if node
        .get("const")
        .and_then(Value::as_i64)
        .is_some_and(|expected| integer != expected)
    {
        return Err(record_error(path, "does not match `const`"));
    }
    if node
        .get("enum")
        .and_then(Value::as_array)
        .is_some_and(|values| !values.iter().any(|item| item.as_i64() == Some(integer)))
    {
        return Err(record_error(path, "is not in `enum`"));
    }
    if node
        .get("minimum")
        .and_then(Value::as_i64)
        .is_some_and(|minimum| integer < minimum)
    {
        return Err(record_error(path, "is below `minimum`"));
    }
    if node
        .get("maximum")
        .and_then(Value::as_i64)
        .is_some_and(|maximum| integer > maximum)
    {
        return Err(record_error(path, "is above `maximum`"));
    }
    Ok(())
}

fn validate_string(
    node: &serde_json::Map<String, Value>,
    path: &str,
    value: &Value,
) -> Result<(), LexiconRecordError> {
    let string = value
        .as_str()
        .ok_or_else(|| record_error(path, "must be a string"))?;
    if node
        .get("const")
        .and_then(Value::as_str)
        .is_some_and(|expected| string != expected)
    {
        return Err(record_error(path, "does not match `const`"));
    }
    if node
        .get("enum")
        .and_then(Value::as_array)
        .is_some_and(|values| !values.iter().any(|item| item.as_str() == Some(string)))
    {
        return Err(record_error(path, "is not in `enum`"));
    }
    check_length(node, path, string.len() as u64)?;
    let graphemes = string.graphemes(true).count() as u64;
    check_bounds(
        node,
        path,
        graphemes,
        "minGraphemes",
        "maxGraphemes",
        "graphemes",
    )?;
    if let Some(format) = node.get("format").and_then(Value::as_str) {
        validate_string_format(format, string).map_err(|reason| record_error(path, reason))?;
    }
    Ok(())
}

fn check_length(
    node: &serde_json::Map<String, Value>,
    path: &str,
    length: u64,
) -> Result<(), LexiconRecordError> {
    check_bounds(node, path, length, "minLength", "maxLength", "length")
}

fn check_bounds(
    node: &serde_json::Map<String, Value>,
    path: &str,
    actual: u64,
    min: &str,
    max: &str,
    label: &str,
) -> Result<(), LexiconRecordError> {
    if node
        .get(min)
        .and_then(Value::as_u64)
        .is_some_and(|bound| actual < bound)
    {
        return Err(record_error(path, format!("{label} is below `{min}`")));
    }
    if node
        .get(max)
        .and_then(Value::as_u64)
        .is_some_and(|bound| actual > bound)
    {
        return Err(record_error(path, format!("{label} is above `{max}`")));
    }
    Ok(())
}

fn validate_bytes(
    node: &serde_json::Map<String, Value>,
    path: &str,
    value: &Value,
) -> Result<(), LexiconRecordError> {
    let encoded = value
        .get("$bytes")
        .and_then(Value::as_str)
        .ok_or_else(|| record_error(path, "must be a byte array"))?;
    if !node.contains_key("minLength") && !node.contains_key("maxLength") {
        return Ok(());
    }
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(encoded))
        .map_err(|_| record_error(path, "contains invalid base64"))?;
    check_length(node, path, bytes.len() as u64)
}

fn validate_cid_link(path: &str, value: &Value) -> Result<(), LexiconRecordError> {
    let map = object(value, path)?;
    if map.len() != 1
        || map
            .get("$link")
            .and_then(Value::as_str)
            .is_none_or(|cid| Cid::try_from(cid).is_err())
    {
        return Err(record_error(path, "must be a CID link"));
    }
    Ok(())
}

fn validate_blob(
    node: &serde_json::Map<String, Value>,
    path: &str,
    value: &Value,
) -> Result<(), LexiconRecordError> {
    let map = object(value, path)?;
    if map.get("$type").and_then(Value::as_str) != Some("blob") {
        return Err(record_error(path, "must be a blob"));
    }
    let mime = map
        .get("mimeType")
        .and_then(Value::as_str)
        .ok_or_else(|| record_error(path, "blob is missing `mimeType`"))?;
    let size = map
        .get("size")
        .and_then(Value::as_u64)
        .ok_or_else(|| record_error(path, "blob is missing integer `size`"))?;
    validate_cid_link(
        &property_path(path, "ref"),
        map.get("ref").unwrap_or(&Value::Null),
    )?;
    if node
        .get("maxSize")
        .and_then(Value::as_u64)
        .is_some_and(|max| size > max)
    {
        return Err(record_error(path, "blob exceeds `maxSize`"));
    }
    if let Some(accept) = node.get("accept").and_then(Value::as_array) {
        let accepted = accept.iter().filter_map(Value::as_str).any(|pattern| {
            pattern == "*/*"
                || pattern == mime
                || pattern
                    .strip_suffix('*')
                    .is_some_and(|prefix| mime.starts_with(prefix))
        });
        if !accepted {
            return Err(record_error(path, "blob MIME type is not accepted"));
        }
    }
    Ok(())
}

fn validate_array(
    doc: &serde_json::Map<String, Value>,
    id: &str,
    node: &serde_json::Map<String, Value>,
    path: &str,
    value: &Value,
) -> Result<(), LexiconRecordError> {
    let items = value
        .as_array()
        .ok_or_else(|| record_error(path, "must be an array"))?;
    check_length(node, path, items.len() as u64)?;
    let item_schema = node
        .get("items")
        .ok_or_else(|| record_error(path, "array schema is missing `items`"))?;
    for (index, item) in items.iter().enumerate() {
        validate_schema(
            doc,
            id,
            item_schema,
            &property_path(path, &index.to_string()),
            item,
        )?;
    }
    Ok(())
}

fn validate_object_schema(
    doc: &serde_json::Map<String, Value>,
    id: &str,
    node: &serde_json::Map<String, Value>,
    path: &str,
    value: &Value,
) -> Result<(), LexiconRecordError> {
    let map = object(value, path)?;
    let required = node.get("required").and_then(Value::as_array);
    if let Some(required) = required {
        for key in required.iter().filter_map(Value::as_str) {
            if !map.contains_key(key) {
                return Err(record_error(
                    path,
                    format!("missing required property `{key}`"),
                ));
            }
        }
    }
    let nullable = node.get("nullable").and_then(Value::as_array);
    if let Some(properties) = node.get("properties").and_then(Value::as_object) {
        for (key, schema) in properties {
            if let Some(property) = map.get(key) {
                if property.is_null()
                    && nullable
                        .is_some_and(|keys| keys.iter().any(|item| item.as_str() == Some(key)))
                {
                    continue;
                }
                validate_schema(doc, id, schema, &property_path(path, key), property)?;
            }
        }
    }
    Ok(())
}

fn validate_unknown(path: &str, value: &Value) -> Result<(), LexiconRecordError> {
    let map = object(value, path)?;
    if map.contains_key("$bytes") || map.get("$type").and_then(Value::as_str) == Some("blob") {
        return Err(record_error(
            path,
            "unknown values must be ordinary objects",
        ));
    }
    Ok(())
}

fn validate_union(
    doc: &serde_json::Map<String, Value>,
    id: &str,
    node: &serde_json::Map<String, Value>,
    path: &str,
    value: &Value,
) -> Result<(), LexiconRecordError> {
    let type_name = value
        .get("$type")
        .and_then(Value::as_str)
        .ok_or_else(|| record_error(path, "union value must be an object with `$type`"))?;
    let refs = node
        .get("refs")
        .and_then(Value::as_array)
        .ok_or_else(|| record_error(path, "union schema is missing `refs`"))?;
    let matched = refs
        .iter()
        .filter_map(Value::as_str)
        .find(|reference| canonical_ref(id, reference) == type_name);
    match matched {
        Some(reference) => {
            validate_schema(doc, id, resolve_ref(doc, id, reference, path)?, path, value)
        }
        None if node.get("closed").and_then(Value::as_bool) == Some(true) => {
            Err(record_error(path, "`$type` is outside the closed union"))
        }
        None => Ok(()),
    }
}

fn canonical_ref(id: &str, reference: &str) -> String {
    if let Some(fragment) = reference.strip_prefix('#') {
        format!("{id}#{fragment}")
    } else if reference.contains('#') {
        reference.to_owned()
    } else {
        format!("{reference}#main")
    }
}

fn resolve_ref<'a>(
    doc: &'a serde_json::Map<String, Value>,
    id: &str,
    reference: &str,
    path: &str,
) -> Result<&'a Value, LexiconRecordError> {
    let canonical = canonical_ref(id, reference);
    let (target_id, fragment) = canonical.split_once('#').unwrap_or((&canonical, "main"));
    if target_id != id {
        return Err(record_error(
            path,
            format!("unresolved external ref `{reference}`"),
        ));
    }
    doc.get("defs")
        .and_then(Value::as_object)
        .and_then(|defs| defs.get(fragment))
        .ok_or_else(|| record_error(path, format!("unresolved ref `{reference}`")))
}

fn validate_record_key(kind: &str, rkey: &str) -> Result<(), LexiconRecordError> {
    let valid = if let Some(literal) = kind.strip_prefix("literal:") {
        rkey == literal
    } else {
        match kind {
            "tid" => is_valid_tid(rkey),
            "nsid" => validate_collection(rkey).is_ok(),
            "any" => is_valid_record_key(rkey),
            _ => false,
        }
    };
    valid
        .then_some(())
        .ok_or_else(|| record_error("record key", format!("does not satisfy `{kind}`")))
}

fn is_valid_record_key(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 512
        && value != "."
        && value != ".."
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'~' | b':' | b'-')
        })
}

fn is_valid_tid(value: &str) -> bool {
    value.len() == 13
        && value
            .bytes()
            .next()
            .is_some_and(|byte| b"234567abcdefghij".contains(&byte))
        && value
            .bytes()
            .all(|byte| b"234567abcdefghijklmnopqrstuvwxyz".contains(&byte))
}

fn validate_string_format(format: &str, value: &str) -> Result<(), &'static str> {
    let valid = match format {
        "did" => crate::at_uri::validate_did(value).is_ok(),
        "handle" => crate::at_uri::validate_handle(value).is_ok(),
        "at-identifier" => {
            if value.starts_with("did:") {
                crate::at_uri::validate_did(value).is_ok()
            } else {
                crate::at_uri::validate_handle(value).is_ok()
            }
        }
        "at-uri" => AtUri::parse(value).is_ok(),
        "nsid" => validate_collection(value).is_ok(),
        "cid" => Cid::try_from(value).is_ok(),
        "datetime" => crate::datetime::is_valid(value),
        "language" => is_valid_language(value),
        "uri" => is_valid_uri(value),
        "tid" => is_valid_tid(value),
        "record-key" => is_valid_record_key(value),
        _ => false,
    };
    valid
        .then_some(())
        .ok_or("does not satisfy its string format")
}

fn is_valid_language(value: &str) -> bool {
    let mut parts = value.split('-');
    parts.next().is_some_and(|first| {
        !first.is_empty()
            && first.len() <= 8
            && first.bytes().all(|byte| byte.is_ascii_alphabetic())
    }) && parts.all(|part| {
        !part.is_empty() && part.len() <= 8 && part.bytes().all(|byte| byte.is_ascii_alphanumeric())
    })
}

fn is_valid_uri(value: &str) -> bool {
    let Some((scheme, rest)) = value.split_once(':') else {
        return false;
    };
    !rest.is_empty()
        && scheme
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_alphabetic())
        && scheme
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'.' | b'-'))
        && !value.chars().any(char::is_whitespace)
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

    #[derive(serde::Deserialize)]
    struct RecordDataCase {
        name: String,
        rkey: String,
        data: Value,
    }

    fn load_record_data(raw: &str) -> Vec<RecordDataCase> {
        let cases: Vec<RecordDataCase> =
            serde_json::from_str(raw).expect("parse record-data vectors");
        assert!(!cases.is_empty(), "record-data vectors must not be empty");
        cases
    }

    fn record_lexicon() -> Value {
        serde_json::from_str(include_str!(
            "../tests/fixtures/interop/lexicon-record.json"
        ))
        .expect("parse record-data lexicon")
    }

    #[test]
    fn accepts_valid_record_data_vectors() {
        let lexicon = record_lexicon();
        let cases = load_record_data(include_str!(
            "../tests/fixtures/interop/record-data-valid.json"
        ));
        for case in &cases {
            assert_eq!(
                validate_record(&lexicon, "main", &case.rkey, &case.data),
                Ok(()),
                "expected valid record-data vector: {}",
                case.name,
            );
        }
    }

    #[test]
    fn rejects_invalid_record_data_vectors() {
        let lexicon = record_lexicon();
        let cases = load_record_data(include_str!(
            "../tests/fixtures/interop/record-data-invalid.json"
        ));
        for case in &cases {
            assert!(
                validate_record(&lexicon, "main", &case.rkey, &case.data).is_err(),
                "expected invalid record-data vector: {} ({:?})",
                case.name,
                case.data,
            );
        }
    }

    #[test]
    #[should_panic(expected = "corrupted valid record-data vector must still validate")]
    fn corrupted_record_data_fixture_is_detected() {
        let lexicon = record_lexicon();
        let mut cases = load_record_data(include_str!(
            "../tests/fixtures/interop/record-data-valid.json"
        ));
        let case = &mut cases[0];
        case.data
            .as_object_mut()
            .expect("valid record is an object")
            .remove("integer");
        assert!(
            validate_record(&lexicon, "main", &case.rkey, &case.data).is_ok(),
            "corrupted valid record-data vector must still validate",
        );
    }
}
