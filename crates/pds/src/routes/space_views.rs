// pattern: Imperative Shell

//! Shared handler-free support for the `com.atproto.space.*` routes (routes may not import one
//! another): space-ref parsing, the `validate`-flag record check, stored-block decoding, and the
//! `{uri, cid, validationStatus}` shape every write route answers with.
//!
//! Authorization is deliberately *not* here — it lives in `auth/space.rs`, the one seam every
//! space route enters through.

use crate::lexicon::RecordValidation;
use crate::space_record_write::SpaceCommitOutcome;
use crate::space_uri::SpaceRef;
use common::{ApiError, ErrorCode};

/// Parse the `space` a request named.
///
/// The lexicon layer's `space-ref` format has already rejected a malformed one before any
/// handler runs, so this only fails for a caller that reached a handler some other way — but it
/// is also the only way the `(authority, type, skey)` triple is obtained, so nothing downstream
/// can be handed a URI that was never checked.
pub fn parse_space(space: &str) -> Result<SpaceRef, ApiError> {
    crate::space_uri::parse_space_ref(space).ok_or_else(|| {
        ApiError::new(
            ErrorCode::InvalidRequest,
            format!("not a space uri: {space}"),
        )
    })
}

/// `assertValidRecord`-parity validation for a space write, exactly as the public repo routes
/// run it: an invalid record of a vendored collection is rejected by default, `validate: true`
/// requires validity, `validate: false` skips, and the outcome is reported as
/// `validationStatus`.
///
/// The write choke point deliberately does not do this — it enforces the schema-free record
/// format gate, and the lexicon-aware half is the route's, so `validate` stays a wire concern.
pub fn validate_record(
    collection: &str,
    rkey: &str,
    record: &serde_json::Value,
    validate: Option<bool>,
) -> Result<Option<RecordValidation>, ApiError> {
    crate::lexicon::registry()
        .validate_record(collection, rkey, record, validate)
        .map_err(crate::record_write::record_validation_error)
}

/// The `{uri, cid, validationStatus}` body a single-record write answers with.
pub fn write_result(
    space: &SpaceRef,
    did: &str,
    collection: &str,
    rkey: &str,
    outcome: &SpaceCommitOutcome,
    validation_status: Option<RecordValidation>,
) -> Result<serde_json::Value, ApiError> {
    let cid = outcome
        .results
        .first()
        .and_then(|result| result.cid.as_deref())
        .ok_or_else(|| {
            tracing::error!(space = %space.uri, did = %did, "space write reported no record cid");
            ApiError::new(ErrorCode::InternalError, "failed to write space record")
        })?;
    let mut body = serde_json::json!({
        "uri": space.record_uri(did, collection, rkey),
        "cid": cid,
    });
    if let Some(status) = validation_status {
        body["validationStatus"] = serde_json::Value::String(status.as_str().to_string());
    }
    Ok(body)
}

/// Decode a stored record block back to JSON (CID links → `{"$link": …}`, byte strings →
/// `{"$bytes": …}`), the same mapping the public record routes serve.
pub fn decode_value(bytes: &[u8]) -> Result<serde_json::Value, ApiError> {
    let ipld = repo_engine::decode_record_block(bytes).map_err(decode_error)?;
    repo_engine::record_value_to_json(&ipld).map_err(decode_error)
}

fn decode_error(e: impl std::fmt::Display) -> ApiError {
    tracing::error!(error = %e, "stored space record block is undecodable");
    ApiError::new(ErrorCode::InternalError, "failed to read space record")
}

/// Lex-JSON encoding of a byte string: `{"$bytes": "<base64>"}`, the JSON form the lexicon
/// `bytes` type takes on the wire.
pub fn lex_bytes(bytes: &[u8]) -> serde_json::Value {
    use base64::Engine as _;
    serde_json::json!({ "$bytes": base64::engine::general_purpose::STANDARD.encode(bytes) })
}
