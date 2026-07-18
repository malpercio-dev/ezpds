// pattern: Imperative Shell
//
// `LexiconParams<T>`: the axum extractor validating an XRPC procedure's query parameters against
// its declared lexicon `parameters` (`type: params`), mirroring `LexiconInput<T>` for bodies. It
// replaces axum's bare `Query<T>` on every natively-handled GET procedure, whose default
// rejection is a 400 with a *plain-text* body (not the reference PDS's `ApiError` envelope), and
// whose strictness is whatever the per-route serde struct happens to enforce.
//
// Query values are always strings, so validation is preceded by a coercion step mirroring
// `@atproto/xrpc-server`'s `decodeQueryParams`/`decodeQueryParam`:
//
//   * An empty value (`?repo=`) decodes to "absent" — identical to the key never being sent at
//     all, so it can still satisfy an optional property but never a required one.
//   * A `string` property is used as-is; an `integer` property is parsed leniently
//     (`parseInt(v, 10) || 0` in the reference) — an unparseable value silently becomes `0`
//     rather than a type error, which can then still fail a `minimum`/`maximum`/`enum` bound; a
//     `boolean` property is `true` only for the literal string `"true"`, anything else (including
//     `"1"`/`"TRUE"`) decodes to `false` — a boolean property can therefore never fail its own
//     type check, only a `const`.
//   * An `array` property is repeated query keys (`cids=a&cids=b`, the one route that previously
//     hand-parsed this with `RawQuery` — `sync.getBlocks`); an empty repetition is dropped
//     element-wise, like a scalar empty value. A key that appears exactly once with an empty
//     value is treated as fully absent (mirroring the reference's `val ? [...] : undefined`,
//     where a single empty string is JS-falsy); two or more repetitions are always "present" even
//     if every individual value is empty, since a non-empty JS array is truthy regardless of its
//     contents.
//   * A key repeated for a *scalar*-typed property is a client shape the reference itself barely
//     defines byte-for-byte (`String(['a','b'])`-style JS coercion); this uses the first
//     occurrence — a reasonable, documented simplification of an undocumented edge case.
//
// Coercion never itself rejects a request — only the shared lexicon-schema validator
// (required/format/bounds/enum) can, exactly as body validation only rejects on schema failure.
//
// Handlers that need to adjust the raw query before validation runs (`get_record.rs`'s legacy
// `did=` alias for the lexicon's `repo` parameter) skip the extractor and call
// `parse_raw_query`/`validate_params_map` directly.

use std::collections::HashMap;

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use serde::de::DeserializeOwned;
use serde_json::Value;

use common::{ApiError, ErrorCode};

use super::schema::LexSchema;
use super::{registry, ValidationError};

/// Raw query-string values, grouped by key in the order they appeared. The pre-coercion shape a
/// caller can still adjust (e.g. renaming a legacy alias key) before handing it to
/// `validate_params_map`.
pub type RawParams = HashMap<String, Vec<String>>;

/// Parse a raw query string (the part after `?`, no leading `?`) into a multi-map preserving
/// repeated keys and their order of appearance, matching `URLSearchParams`.
pub fn parse_raw_query(query: &str) -> Result<RawParams, ApiError> {
    let mut raw: RawParams = HashMap::new();
    for pair in query.split('&').filter(|p| !p.is_empty()) {
        let (raw_key, raw_value) = pair.split_once('=').unwrap_or((pair, ""));
        let key = urlencoding::decode(raw_key)
            .map_err(|_| ApiError::new(ErrorCode::InvalidRequest, "invalid query encoding"))?
            .into_owned();
        let value = urlencoding::decode(raw_value)
            .map_err(|_| ApiError::new(ErrorCode::InvalidRequest, "invalid query encoding"))?
            .into_owned();
        raw.entry(key).or_default().push(value);
    }
    Ok(raw)
}

/// Coerce and validate `raw` against `nsid`'s declared lexicon `parameters`, returning the
/// resulting JSON object (`Value::Object`) ready for `serde_json::from_value` into a handler's
/// params struct. Errors are 400 `InvalidRequest` with the reference PDS's message shapes, except
/// a broken vendored lexicon (unreachable; registry-build-checked) or an nsid with no vendored
/// query/procedure at all, which is a 500 (a wiring defect, not a client error).
pub fn validate_params_map(nsid: &str, raw: &RawParams) -> Result<Value, ApiError> {
    let Some(params) = registry().params(nsid) else {
        tracing::error!(
            nsid,
            "no vendored lexicon params are registered for procedure"
        );
        return Err(ApiError::new(
            ErrorCode::InternalError,
            "server lexicon configuration error",
        ));
    };

    let mut map = serde_json::Map::new();
    for (name, schema) in &params.properties {
        if let Some(value) = coerce_property(schema, raw.get(name)) {
            map.insert(name.clone(), value);
        }
    }
    let value = Value::Object(map);

    registry()
        .validate_params(nsid, &value)
        .map_err(|e| match e {
            ValidationError::Invalid(message) => ApiError::new(ErrorCode::InvalidRequest, message),
            ValidationError::Lexicon(message) => {
                tracing::error!(nsid, error = %message, "vendored lexicon set is inconsistent");
                ApiError::new(
                    ErrorCode::InternalError,
                    "server lexicon configuration error",
                )
            }
        })?;
    Ok(value)
}

/// Coerce one property's raw query values (if any) into its typed JSON value, or `None` when the
/// property should be treated as absent — see the module doc for the exact rules.
fn coerce_property(schema: &LexSchema, raw: Option<&Vec<String>>) -> Option<Value> {
    let values = raw?;
    match schema {
        LexSchema::Array { items, .. } => {
            // "Present" iff the reference's raw (pre-decode) value would be JS-truthy: a single
            // occurrence must be non-empty; two or more occurrences are always truthy (a
            // non-empty JS array), even if every individual value is empty.
            let present = match values.len() {
                0 => false,
                1 => !values[0].is_empty(),
                _ => true,
            };
            if !present {
                return None;
            }
            let coerced: Vec<Value> = values
                .iter()
                .filter(|v| !v.is_empty())
                .filter_map(|v| coerce_scalar(items, v))
                .collect();
            Some(Value::Array(coerced))
        }
        _ => {
            // A repeated key for a scalar-typed property — see the module doc's simplification.
            let raw_value = values.first()?;
            coerce_scalar(schema, raw_value)
        }
    }
}

/// Coerce a single raw (already url-decoded) query value into JSON, mirroring
/// `@atproto/xrpc-server`'s `decodeQueryParam`. Both call sites above filter out an empty `raw`
/// before reaching here (the reference's "falsy value decodes to absent" rule).
fn coerce_scalar(schema: &LexSchema, raw: &str) -> Option<Value> {
    if raw.is_empty() {
        return None;
    }
    Some(match schema {
        LexSchema::String { .. } => Value::String(raw.to_owned()),
        LexSchema::Integer { .. } => Value::Number(parse_int_lenient(raw).into()),
        LexSchema::Boolean { .. } => Value::Bool(raw == "true"),
        _ => unreachable!(
            "params properties are restricted to string/integer/boolean/array by the parser \
             (schema::parse_param_property)"
        ),
    })
}

/// `parseInt(value, 10) || 0`: parse a leading optional sign plus decimal digits, ignoring
/// anything after; no valid digits (or an overflowing parse) falls back to `0` rather than
/// erroring — the reference lets an out-of-range value fail its `minimum`/`maximum`/`enum` bound
/// instead of rejecting it as a type error.
fn parse_int_lenient(raw: &str) -> i64 {
    let trimmed = raw.trim_start();
    let mut end = 0;
    let mut saw_digit = false;
    for (i, c) in trimmed.char_indices() {
        if i == 0 && (c == '+' || c == '-') {
            end = c.len_utf8();
            continue;
        }
        if c.is_ascii_digit() {
            end = i + c.len_utf8();
            saw_digit = true;
        } else {
            break;
        }
    }
    if !saw_digit {
        return 0;
    }
    trimmed[..end].parse::<i64>().unwrap_or(0)
}

/// Validate `query` (the raw string after `?`, no leading `?`) as `nsid`'s lexicon params and
/// return the coerced JSON object on success. The same pipeline `LexiconParams` runs, for a
/// handler that needs the raw query string parsed some other way too.
pub fn validate_procedure_params(nsid: &str, query: &str) -> Result<Value, ApiError> {
    let raw = parse_raw_query(query)?;
    validate_params_map(nsid, &raw)
}

/// Extractor wrapper: lexicon-validate the query parameters for the procedure named by the
/// request path (`/xrpc/<nsid>`), then deserialize them into `T`. Reads only the request head
/// (`FromRequestParts`), so — unlike `LexiconInput`, which consumes the body — it composes freely
/// with other extractors and does not need to be last.
#[derive(Debug)]
pub struct LexiconParams<T>(pub T);

impl<S, T> FromRequestParts<S> for LexiconParams<T>
where
    S: Send + Sync,
    T: DeserializeOwned,
{
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let path = parts.uri.path();
        let nsid = path.strip_prefix("/xrpc/").unwrap_or(path).to_owned();
        let query = parts.uri.query().unwrap_or_default();
        let value = validate_procedure_params(&nsid, query)?;
        let parsed: T = serde_json::from_value(value).map_err(|e| {
            ApiError::new(
                ErrorCode::InvalidRequest,
                format!("invalid query parameters: {e}"),
            )
        })?;
        Ok(LexiconParams(parsed))
    }
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use serde::Deserialize;
    use serde_json::json;

    use super::*;

    fn expect_ok(nsid: &str, query: &str) -> Value {
        validate_procedure_params(nsid, query).unwrap_or_else(|e| panic!("{nsid}?{query}: {e}"))
    }

    fn expect_err(nsid: &str, query: &str) -> String {
        validate_procedure_params(nsid, query)
            .unwrap_err()
            .to_string()
    }

    #[test]
    fn empty_value_is_treated_as_absent() {
        // `?repo=` (empty) must not satisfy `repo` any more than omitting it outright.
        assert!(expect_err("com.atproto.repo.describeRepo", "repo=")
            .ends_with("Params must have the property \"repo\""));
    }

    #[test]
    fn integer_coercion_is_lenient_and_falls_back_to_zero() {
        // An unparseable integer decodes to 0 (not a type error) and then fails its own bound.
        assert!(expect_err(
            "com.atproto.repo.listRecords",
            "repo=did:plc:abc123abc123abc123abc123&collection=app.bsky.feed.post&limit=notanumber"
        )
        .ends_with("Params/limit can not be less than 1"));
        // A valid leading-digit prefix parses like `parseInt`.
        let value = expect_ok(
            "com.atproto.repo.listRecords",
            "repo=did:plc:abc123abc123abc123abc123&collection=app.bsky.feed.post&limit=42abc",
        );
        assert_eq!(value["limit"], json!(42));
    }

    #[test]
    fn boolean_coercion_only_true_literal_is_true() {
        let value = expect_ok(
            "com.atproto.repo.listRecords",
            "repo=did:plc:abc123abc123abc123abc123&collection=app.bsky.feed.post&reverse=yes",
        );
        assert_eq!(value["reverse"], json!(false));
        let value = expect_ok(
            "com.atproto.repo.listRecords",
            "repo=did:plc:abc123abc123abc123abc123&collection=app.bsky.feed.post&reverse=true",
        );
        assert_eq!(value["reverse"], json!(true));
    }

    #[test]
    fn array_param_collects_repeated_keys_and_drops_empty_ones() {
        let cid = "bafyreidfayvfuwqa7qlnopdjiqrxzs6blmoeu4rujcjtnci5beludirz2a";
        let value = expect_ok(
            "com.atproto.sync.getBlocks",
            &format!("did=did:plc:abc123abc123abc123abc123&cids={cid}&cids=&cids={cid}"),
        );
        assert_eq!(value["cids"], json!([cid, cid]));
    }

    #[test]
    fn array_param_absent_key_is_omitted_not_empty_array() {
        assert!(expect_err(
            "com.atproto.sync.getBlocks",
            "did=did:plc:abc123abc123abc123abc123"
        )
        .ends_with("Params must have the property \"cids\""));
    }

    #[test]
    fn unknown_query_keys_are_ignored() {
        let value = expect_ok(
            "com.atproto.repo.describeRepo",
            "repo=did:plc:abc123abc123abc123abc123&unexpected=1",
        );
        assert!(value.get("unexpected").is_none());
    }

    #[derive(Debug, Deserialize)]
    struct DescribeRepoShape {
        repo: String,
    }

    async fn extract(request: Request<Body>) -> Result<LexiconParams<DescribeRepoShape>, ApiError> {
        let (mut parts, _) = request.into_parts();
        LexiconParams::<DescribeRepoShape>::from_request_parts(&mut parts, &()).await
    }

    #[tokio::test]
    async fn extractor_derives_nsid_from_request_path() {
        let request = Request::builder()
            .uri("/xrpc/com.atproto.repo.describeRepo?repo=did:plc:abc123abc123abc123abc123")
            .body(Body::empty())
            .unwrap();
        let extracted = extract(request).await.expect("valid params");
        assert_eq!(extracted.0.repo, "did:plc:abc123abc123abc123abc123");
    }

    #[tokio::test]
    async fn extractor_rejection_is_invalid_request_envelope() {
        let request = Request::builder()
            .uri("/xrpc/com.atproto.repo.describeRepo")
            .body(Body::empty())
            .unwrap();
        let err = extract(request).await.unwrap_err();
        assert_eq!(err.status_code(), StatusCode::BAD_REQUEST.as_u16());
        assert!(
            err.to_string()
                .ends_with("Params must have the property \"repo\""),
            "{err}"
        );
    }
}
