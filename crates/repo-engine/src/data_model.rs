// pattern: Functional Core
//
//! Validation of the ATProto **data model** — the value space that maps to canonical
//! DAG-CBOR (`https://atproto.com/specs/data-model`). This is the layer *below* lexicons:
//! it asks "is this JSON a well-formed ATProto value at all?", independent of any schema.
//!
//! [`json_to_record_value`](crate::records::json_to_record_value) *converts* a record into
//! the data model on the write path, but it is deliberately narrow — it silently accepts a
//! map carrying a stray `$type: null` or a `{"$link": …, "other": …}` with an extra key,
//! and it rejects an integer-valued float (`123.0`) the data model *does* permit. This
//! module is the strict acceptance/rejection oracle the interop `data-model-valid.json` /
//! `data-model-invalid.json` vectors gate against, so the two are not interchangeable.
//!
//! Rules enforced (each backed by an interop vector):
//!
//! * The top-level value must be a map (object). A bare string/number/array is not a record.
//! * Numbers must be integers. An integer-valued float (`123.0`) is accepted and treated as
//!   the integer; a fractional float (`123.456`) is rejected — the data model has no floats.
//! * A map's reserved `$type` field, when present, must be a non-empty string.
//! * A `{"$link": …}` map is a CID link: it must have *exactly* that one key and a value that
//!   parses as a CID. An extra key or a non-string/invalid CID is rejected.
//! * A `{"$bytes": …}` map is a byte string: exactly one key, value a valid base64 string.
//! * A `{"$type": "blob", …}` map is a typed blob: it must carry `ref` (a CID link),
//!   `mimeType` (string), and `size` (integer).

use crate::Cid;
use base64::Engine;
use serde_json::Value;

/// A data-model validation failure. Carries a human-readable reason and the JSON pointer-ish
/// path to the offending value (`` for the root, `arr/2` for the third array element, etc.),
/// so a rejection message names *where* the value went wrong rather than only *that* it did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataModelError {
    pub path: String,
    pub reason: String,
}

impl std::fmt::Display for DataModelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.path.is_empty() {
            write!(f, "data model: {}", self.reason)
        } else {
            write!(f, "data model at `{}`: {}", self.path, self.reason)
        }
    }
}

impl std::error::Error for DataModelError {}

/// Validate that `value` is a well-formed ATProto data-model value.
///
/// The top-level value must be a map; nested values are validated recursively. Returns the
/// first violation encountered, with its path.
pub fn validate(value: &Value) -> Result<(), DataModelError> {
    match value {
        Value::Object(_) => validate_value(value, String::new()),
        _ => Err(DataModelError {
            path: String::new(),
            reason: "top-level value must be an object".into(),
        }),
    }
}

fn err(path: &str, reason: impl Into<String>) -> DataModelError {
    DataModelError {
        path: path.to_string(),
        reason: reason.into(),
    }
}

/// Join a path prefix and a key into a `parent/child` path (no leading slash at the root).
fn child(path: &str, key: &str) -> String {
    if path.is_empty() {
        key.to_string()
    } else {
        format!("{path}/{key}")
    }
}

fn validate_value(value: &Value, path: String) -> Result<(), DataModelError> {
    match value {
        Value::Null | Value::Bool(_) | Value::String(_) => Ok(()),
        Value::Number(n) => validate_number(n, &path),
        Value::Array(items) => {
            for (i, item) in items.iter().enumerate() {
                validate_value(item, child(&path, &i.to_string()))?;
            }
            Ok(())
        }
        Value::Object(map) => validate_object(map, path),
    }
}

/// The data model permits only integers. serde_json keeps `123` and `123.0` distinct (the
/// latter is stored as an `f64`), so an integer-valued float still arrives here as `is_f64`.
/// It is accepted (the reference treats it as the integer); a float with a fractional part is
/// the rejection the `"float"` vector pins.
fn validate_number(n: &serde_json::Number, path: &str) -> Result<(), DataModelError> {
    if n.is_i64() || n.is_u64() {
        return Ok(());
    }
    match n.as_f64() {
        Some(f) if f.is_finite() && f.fract() == 0.0 => Ok(()),
        _ => Err(err(
            path,
            "number must be an integer (the data model has no floats)",
        )),
    }
}

fn validate_object(
    map: &serde_json::Map<String, Value>,
    path: String,
) -> Result<(), DataModelError> {
    // `{"$link": …}` — a CID link. Reserved: presence of `$link` forces the exact shape.
    if map.contains_key("$link") {
        return validate_cid_link(map, &path);
    }
    // `{"$bytes": …}` — a byte string.
    if map.contains_key("$bytes") {
        return validate_bytes(map, &path);
    }
    // `{"$type": "blob", …}` — a typed blob reference.
    if matches!(map.get("$type"), Some(Value::String(t)) if t == "blob") {
        return validate_blob(map, &path);
    }

    // A general object. `$type`, if present, must be a non-empty string (it names the value's
    // lexicon); every value is validated recursively.
    if let Some(ty) = map.get("$type") {
        match ty {
            Value::String(s) if !s.is_empty() => {}
            _ => return Err(err(&path, "`$type` must be a non-empty string")),
        }
    }
    for (k, v) in map {
        validate_value(v, child(&path, k))?;
    }
    Ok(())
}

fn validate_cid_link(
    map: &serde_json::Map<String, Value>,
    path: &str,
) -> Result<(), DataModelError> {
    if map.len() != 1 {
        return Err(err(path, "a `$link` object must have exactly one key"));
    }
    match map.get("$link") {
        Some(Value::String(s)) => Cid::try_from(s.as_str())
            .map(|_| ())
            .map_err(|e| err(path, format!("`$link` is not a valid CID: {e}"))),
        _ => Err(err(path, "`$link` must be a string")),
    }
}

fn validate_bytes(map: &serde_json::Map<String, Value>, path: &str) -> Result<(), DataModelError> {
    if map.len() != 1 {
        return Err(err(path, "a `$bytes` object must have exactly one key"));
    }
    match map.get("$bytes") {
        Some(Value::String(s)) => base64::engine::general_purpose::STANDARD
            .decode(s)
            .map(|_| ())
            .map_err(|e| err(path, format!("`$bytes` is not valid base64: {e}"))),
        _ => Err(err(path, "`$bytes` must be a string")),
    }
}

fn validate_blob(map: &serde_json::Map<String, Value>, path: &str) -> Result<(), DataModelError> {
    // ref: a CID link.
    match map.get("ref") {
        Some(Value::Object(r)) if r.contains_key("$link") => {
            validate_cid_link(r, &child(path, "ref"))?;
        }
        Some(_) => {
            return Err(err(
                path,
                "blob `ref` must be a CID link (`{\"$link\": …}`)",
            ))
        }
        None => return Err(err(path, "blob is missing the `ref` key")),
    }
    // mimeType: a string.
    match map.get("mimeType") {
        Some(Value::String(_)) => {}
        Some(_) => return Err(err(path, "blob `mimeType` must be a string")),
        None => return Err(err(path, "blob is missing the `mimeType` key")),
    }
    // size: an integer.
    match map.get("size") {
        Some(Value::Number(n)) if n.is_i64() || n.is_u64() => {}
        Some(_) => return Err(err(path, "blob `size` must be an integer")),
        None => return Err(err(path, "blob is missing the `size` key")),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One entry of the interop `data-model-{valid,invalid}.json` vectors. The valid set keys
    /// the payload under `json`; the invalid set uses the same `json` key (both carry a `note`).
    #[derive(serde::Deserialize)]
    struct DataModelCase {
        note: String,
        json: Value,
    }

    fn load(raw: &str) -> Vec<DataModelCase> {
        let cases: Vec<DataModelCase> =
            serde_json::from_str(raw).expect("parse data-model vectors");
        assert!(!cases.is_empty(), "data-model vectors must not be empty");
        cases
    }

    #[test]
    fn accepts_valid_data_model_vectors() {
        let cases = load(include_str!(
            "../tests/fixtures/interop/data-model-valid.json"
        ));
        for c in &cases {
            assert!(
                validate(&c.json).is_ok(),
                "expected valid ({}): {:?} -> {:?}",
                c.note,
                c.json,
                validate(&c.json),
            );
        }
    }

    #[test]
    fn rejects_invalid_data_model_vectors() {
        let cases = load(include_str!(
            "../tests/fixtures/interop/data-model-invalid.json"
        ));
        for c in &cases {
            assert!(
                validate(&c.json).is_err(),
                "expected invalid ({}): {:?} was accepted",
                c.note,
                c.json,
            );
        }
    }

    #[test]
    #[should_panic(expected = "corrupted valid vector must still validate")]
    fn corrupted_data_model_fixture_is_detected() {
        // Mutate a known-good vector into a known-bad one (a fractional float) and assert it
        // still validates — it must not, tripping the gate. Proves the validator has teeth and
        // the acceptance test above is not vacuously passing.
        let corrupt = serde_json::json!({ "rcrd": { "a": 123.456 } });
        assert!(
            validate(&corrupt).is_ok(),
            "corrupted valid vector must still validate",
        );
    }
}
